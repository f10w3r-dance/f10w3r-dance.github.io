---
layout: post
date: 2020-01-10
title: "2020년 1월 리눅스 커널 익스플로잇 시작하기전 commit_creds 공부"
author: "f10w3r"
tags: linux kernel exploit pwn
---

### commit_creds 분석

`commit_creds` 함수의 소스코드는 [여기서](https://elixir.bootlin.com/linux/v4.18/source/kernel/cred.c#L423) 확인 하실수 있습니다. 

제일 먼저 commit_creds 함수에서는 현재 프로세스가 사용중인 자격 증명과 curren가 가지고 있는 자격 증명이 같은지 확인합니다. 

이어서 `new`의 `usage` 변수가 1이하 인지 검사합니다.

하지만, `prepare_kernel_cred`함수에서 `new->usage`를 1로 설정했기 때문에 스무스 하게 통과합니다. 

추가로 설명하자면, `BUG_ON` 매크로는 인자가 참이라면, 예외처리를 진행합니다.

```c
int commit_creds(struct cred *new)
{
	struct task_struct *task = current;
	const struct cred *old = task->real_cred;

	kdebug("commit_creds(%p{%d,%d})", new,
	       atomic_read(&new->usage),
	       read_cred_subscribers(new));

	BUG_ON(task->cred != old);
#ifdef CONFIG_DEBUG_CREDENTIALS
	BUG_ON(read_cred_subscribers(old) < 2);
	validate_creds(old);
	validate_creds(new);
#endif
    BUG_ON(atomic_read(&new->usage) < 1);
```

그리고, new의 자격 증명 정보를 가져와 기존에 설정된 `old`와 각 `uid, gid`가 동일한지 검사한다. 그리고 다른 부분(`fs[u/g]id`, `e[u/g]id`의 uid, qid)이 있다면, 데이터를 갱신한다.

- fs/uid: 파일 시스템에 대한 접근 권한
- eu/gid: 프로세스가 가지는 파일에 대한 접근 제한에 사용되며 파일 시스템 사용자 아이디

```c
	get_cred(new); /* we will require a ref for the subj creds too */

	/* dumpability changes */
	if (!uid_eq(old->euid, new->euid) ||
	    !gid_eq(old->egid, new->egid) ||
	    !uid_eq(old->fsuid, new->fsuid) ||
	    !gid_eq(old->fsgid, new->fsgid) ||
	    !cred_cap_issubset(old, new)) {
		if (task->mm)
			set_dumpable(task->mm, suid_dumpable);
		task->pdeath_signal = 0;
		smp_wmb();
	}

    /* alter the thread keyring */
	if (!uid_eq(new->fsuid, old->fsuid))
		key_fsuid_changed(task);
	if (!gid_eq(new->fsgid, old->fsgid))
		key_fsgid_changed(task);
```


이후에 `new`의 `subscribers` 변수에 2를 더한다. 2가 더해진 값은 현재 프로세스에 대한 자격 증명이 등록된 상태를 뜻하는거 같다.

그리고 `rcu`방식으로 `task->real_cred`, `task->cred`의 값에 `new`의 자격 증명 정보를 저장한다.

이후 이전(`old`)의 `subscribers`의 값을 2만큼 내린다.

그리고 이전에 사용된 자격 증명을 모두 해제한다.

```c
	alter_cred_subscribers(new, 2);
	if (new->user != old->user)
		atomic_inc(&new->user->processes);
	rcu_assign_pointer(task->real_cred, new);
	rcu_assign_pointer(task->cred, new);
	if (new->user != old->user)
		atomic_dec(&old->user->processes);
	alter_cred_subscribers(old, -2);

	/* send notifications */
	if (!uid_eq(new->uid,   old->uid)  ||
	    !uid_eq(new->euid,  old->euid) ||
	    !uid_eq(new->suid,  old->suid) ||
	    !uid_eq(new->fsuid, old->fsuid))
		proc_id_connector(task, PROC_EVENT_UID);

	if (!gid_eq(new->gid,   old->gid)  ||
	    !gid_eq(new->egid,  old->egid) ||
	    !gid_eq(new->sgid,  old->sgid) ||
	    !gid_eq(new->fsgid, old->fsgid))
		proc_id_connector(task, PROC_EVENT_GID);

	/* release the old obj and subj refs both */
	put_cred(old);
	put_cred(old);
	return 0;
```

이런식으로 새로운 자격증명을 등록하는 함수이다. 결론적으로 `prepare_kernel_cred` 함수로 새로운 루트 자격증명을 생성하여 `commit_creds`로 현재 프로세스에 root의 자격증명을 등록하는 방식으로 권한 상승을 시도한다.

이렇게 되면 실행 흐름을 컨트롤 할 수 있을때 커널 드라이버에 IOCTL을 송신한 유저 프로세스의 권한이 root로 상승한다. 
- `commit_creds(prepare_kernel_cred(0))`

IOCTL의 구현 코드는 아래 처럼 등록될 수 있다.

```c
#define LPE 0x41410001
...
case LPE:
    commit_creds(prepare_kernel_cred(0));
    return 0;
...
```
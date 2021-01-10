---
layout: post
date: 2020-01-10
title: "2020년 1월 리눅스 커널 익스플로잇 시작하기전 prepare_kernel_cred 공부"
author: "f10w3r"
tags: linux kernel exploit pwn
---

### 시작하기전

안녕하세요 f10w3r 입니다.

오늘은 오랜만에 평화로운 주말을 얻어 임베디드를 공부할지, 포스팅하다 도중에 멈춘 악성코드를 계속 적을지, 새로운걸 공부 해볼지 고민하다 갑작스럽게 QEMU가 궁금해져 리눅스 커널을 공부하게 되었습니다.

너무 갑작스럽게 시작하여 뭐부터 공부해야할지 막막해서 일단 CTF 문제 부터 풀어보자는 마음으로 시작했습니다.

포스팅에 사용된 문제는 `QWB CTF 2018 core` 문제 입니다.

많은 해커분들이 이 문제로 많은 공부를 하신거 같아 이 길을 따라가보려 합니다 ^_^..

BOB 당시 안티바이러스의 Kernel 취약점을 찾는 프로젝트를 해본 경험이 있어 유저 프로세스와 커널간 통신이 어떻게 이루어지는지, 권한 상승을 위해 유저 프로세스를 높은 권한으로 변경하는 기법이 생각나 리눅스에서도 같은 기법으로 권한 상승을 하는지 찾아봤는데 `prepare_kernel_cred`와 `commit_creds` 함수가 있습니다.

두개의 함수를 간단하게 먼저 알아보면 해당 함수의 기능은 아래와 같습니다.

- `prepare_kernel_cred`: 인자를 0으로 주면 root 권한의 자격 증명 정보가 담긴 구조체를 뱉어 줍니다.

- `commit_creds`: 인자를 prepare_kernel_cred의 리턴값으로 주면, 자격 증명 정보를 현재 프로세스에 설치합니다. 그리고 이전에 있던 자격증명을 해제 합니다. 

이런식으로 구성 되어있다. 사실 여기까지만 봐도, 당장 문제를 풀어보려고 했는데 문득 함수 두개가 어떻게 구성 되어있는지 궁금했습니다.

예전에 안티바이러스 프로젝트를 할때는 사실 이런 권한 상승 기법에 대해서는 별로 안궁금했다.. 그냥 취약점을 많이 찾고 익스플로잇을 하면 만만세 였는데 지금와서 생각해보면 이러한 동작 구조가 매우 매우 중요하다고 생각이 듭니다.

그래서 하나씩 천천히 공부해보려고 해보겠습니다.


### prepare_kernel_cred 분석

일단, `prepare_kernel_cred` 함수의 소스코드는 [여기서](https://elixir.bootlin.com/linux/v4.18/source/kernel/cred.c#L595) 확인 하실수 있습니다. 

`prepare_kernel_cred` 함수 내부는 malloc 코드와는 다르게 생각보다 짧아 놀랐습니다. 코드는 아래와 같습니다. 

![pic1](pic/prepare_kernel_cred.png?raw=true)

제일 먼저 `task_struct *daemon`의 인자가 `0`이라면, `old`변수에 `&init_cred`를 `get_cred`로 가져와 설정합니다. 

```c
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred)

....
```

재미난점은 `&init_cred` 구조체를 기본적으로 root의 권한으로 구성 되어있다. 그래서, 선언된 코드를 한번 보면 아래와 같다. 뭔가 나중에 문제 같은거 풀 때 이런거 한번씩 만들어서 써야할거 같은 상황이 올거같다.. 

```c
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
};
```

아무튼, 이렇게 생성된 `old` 변수에 담겨진 자격 증명 정보가 정상적인지 검사하는 코드가 실행 됩니다.

```c
kdebug("prepare_kernel_cred() alloc %p", new);

if (daemon)
    old = get_task_cred(daemon);
else
    old = get_cred(&init_cred);

validate_creds(old);
```

근데 여기서 `validate_creds`가 어떻게 동작하는지 잠깐 궁금해서 코드를 찾아보니까 아래처럼 언링크 되어있는지 검사하는거 같다.
```c
static inline void __validate_creds(const struct cred *cred,
				    const char *file, unsigned line)
{
	if (unlikely(creds_are_invalid(cred)))
		__invalid_creds(cred, file, line);
}
```

계속 코드를 분석해보면 `security_prepare_creds` 함수를 통해 새로운 자격 증명을 설치한다. 그리고 `put_cred` 함수를 통해 기존의 자격 증명을 해제한다.

```c
	*new = *old;
	atomic_set(&new->usage, 1);
	set_cred_subscribers(new, 0);
	get_uid(new->user);
	get_user_ns(new->user_ns);
	get_group_info(new->group_info);

#ifdef CONFIG_KEYS
	new->session_keyring = NULL;
	new->process_keyring = NULL;
	new->thread_keyring = NULL;
	new->request_key_auth = NULL;
	new->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
#endif

#ifdef CONFIG_SECURITY
	new->security = NULL;
#endif
	if (security_prepare_creds(new, old, GFP_KERNEL) < 0)
		goto error;

	put_cred(old);
	validate_creds(new);
	return new;

error:
	put_cred(new);
	put_cred(old);
	return NULL;
```

잠깐의 TMI지만 `security_prepare_creds` 함수가 뭔지 몰라 한참 코드를 찾다 아래 같은걸 찾아서 그냥 납득하기로 했다 휴... `나중에 다시 한번 블로그를 보면서 이게 이런거였구나 하고 미래의 내가 다시 공부할때는 그냥 빠르게 포기하고 납득하길 바란다..`
```
 * @cred_prepare:
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Prepare a new set of credentials by copying the data from the old set.
```

그리고 더 이해안되는 `put_cred`의 의미심장한 이름의 함수였는데 뭔가 자격증명을 넣을것만 같은 이름이었으나,, 반대로 해제 한다고한다.

대충 돌아가는 구조는 그렇다. `atomic_set(&new->usage, 1);`을 설정한 상황 처럼 `usage`를 비교하여 기존에 새로운 자격 증명을 해제하는 친구다. 기본적으로 usage가 1일때는 동작하지 않는다. 내부적으로 `dec` 후 `test` 인라인 어셈으로 비교하여 분기를 진행한다. 아무튼 0이면 동작하지 않는다.

다시 코드 분석으로 돌아가, 분석을 해보면 그이후엔 그냥 `new`를 리턴한다.

이렇게 생성과 리턴된 `new` 자격 증명을 이용하여 `commit_creds`를 통해 설치한다. 다음 포스팅에서는 `commit_creds`를 알아보려고 한다.
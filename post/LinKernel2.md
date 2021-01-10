---
layout: post
date: 2020-01-10
title: "2020년 1월 리눅스 커널 익스플로잇 시작하기전 commit_creds 공부"
author: "f10w3r"
tags: linux kernel exploit pwn
---

두번째 리눅스 커널 공부 포스팅 바로 시작해보겠습니다!

### commit_creds 분석

`commit_creds` 함수의 소스코드는 [여기서](https://elixir.bootlin.com/linux/v4.18/source/kernel/cred.c#L423) 확인 하실수 있습니다. 


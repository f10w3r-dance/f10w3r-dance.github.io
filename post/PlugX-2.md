---
layout: post
date: 2020-12-21
title: "2020년 11월 PlugX 분석 이야기 2편(Stage1 분석)"
author: "f10w3r"
tags: malware apt41 plugx
---

[2020년 11월 PlugX 분석 이야기 1편(샘플 확보) 보러 가기](PlugX-1.md)

지난 시간에 이어 샘플 확보를 완료했습니다. 이제 본격적인 분석을 시작해보죠!

이전글에서 확인했지만, `C4164EFA57204AD32AEC2B0F1A12BB3A` 샘플은 `license.rtf` 파일을 읽어 메모리상에서 쉘코드를 실행하는 구조를 가지고 있는 악성코드 입니다.(아래 그림을 참고해주세요.)

![pic1](pic/ida_screen.png?raw=true)


일단 APT41은 기본적으로 쉘코드를 매우 사랑하는 조직인듯 합니다.(글쓴이 피셜) 이 그룹을 분석할 때면, 항상 분석하기가 싫군요 ㅎㅎ..

![pic2](pic/fuckingshellcode.jpg?raw=true)


제일 먼저 `C4164EFA57204AD32AEC2B0F1A12BB3A` 악성코드는 `license.rtf`의 데이터를 읽어와 `VirtualAlloc` 함수를 통해 실행 가능한 메모리를 할당 받고 데이터를 읽어옵니다.

![pic3](pic/스크린샷%202020-12-20%20오후%2010.39.37.png?raw=true)


그리고는 무자비하게도 뒤도 안돌아보고 바로 쉘코드로 점프 해버립니다.

![pic4](pic/스크린샷%202020-12-20%20오후%2010.42.06.png?raw=true)


방금 분석으로 우리는 무려 당연하지만 중요한 2가지 정보를 얻었습니다! 

1. 쉘코드는 맨 처음부터 실행된다.
2. license.rtf 파일은 암호화 혹은 인코딩 되어있지 않았을것이다.

따라서 재빨리 `license.rtf` 파일을 분석 해보겠습니다.
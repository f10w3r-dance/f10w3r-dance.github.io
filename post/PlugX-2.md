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

제일 먼저 `license.rtf`를 IDA를 통해 확인해보면 예쁜 hex-ray가 우리를 기다려주고 있을겁니다.

![pic5](pic/스크린샷%202020-12-20%20오후%2011.28.15.png)


... 후...

![pic6](pic/fuckingshellcode.jpg?raw=true)


마음을 진정시키고 차근차근 분석 해보겠습니다. 여러분도 진정하세요..!

제일 먼저 눈에 들어오는건 이 부분입니다.
```asm
push    12CF1h
call    near ptr dword_1283C+4BFh
```

전 제일 먼저 인자로 들어가는 `push    12CF1h` 이 부분이 수상해 보였습니다. 

`f10w3r: 동작 그만, 밑장 깔기냐? 너는 지금 오프셋을 스택에다 깔았어 그리고 코드 밑에 정상적인 ret이 없는걸 보니까 call 안에서 함수 프롤로그 따위는 없는거 겠지 그럼 너는 call 호출시에 스택에 깔리는 다음 instruction의 주소에 니가 넣어준 오프셋을 더해서 뭔가 조잡한짓을 할것이야 내가 빙다리 핫바지로 보이냐 이 새끼야?`

![pic7](pic/밑장빼기냐.jpeg)


이어서 호출되는 `call near ptr dword_1283C+4BFh`는 아래와 같습니다.

![pic8](pic/스크린샷%202020-12-20%20오후%2011.37.55.png)

역시 함수 프롤로그는 없군요 방금전과 같은 방식으로 인자를 하나 더 설정하고 다음 `sub_14211`을 호출 합니다.

`sub_14211` 함수를 보기전 `sub_14211` 함수 호출 직후 잠시 잠시 스택 상황을 먼저 그려보면 아래와 같을겁니다.

|스택(아래가 높은 주소)|
|------|
|12D05h(call 다음 ins)|
|150Ch(push로 넣은 값)|
|0Ah(call다음 ins)|
|12CF1h(push로 넣은 값)|


이렇게 스택 구조를 기억해 놓은 뒤 `sub_14211`를 확인해보면 내부에서 함수 `sub_14217`를 호출하고 정상적으로 `return`하는 모습을 확인할 수 있습니다.

```
seg000:00014211 sub_14211       proc near               ; CODE XREF: seg000:00012D00↑p
seg000:00014211                 call    sub_14217
seg000:00014216                 retn
seg000:00014216 sub_14211       endp ; sp-analysis failed
```

 `sub_14217` 함수 내부로 들어 가보면, 정상적으로 함수 프롤로그를 실행하는것을 확인할 수 있으며, 이는 다시 말해 위에서 `push`와 `call`로 스택에 넣은 값들이 `sub_14217`의 인자로 설정된 것을 예상 할 수 있습니다. 해당 함수의 경우 정상적인 구조를 가지고 있기 떄문에 함수로 인식되어 IDA에서 hex-ray 코드로 변환이 가능합니다.

 ![pic9](./pic/스크린샷%202020-12-20%20오후%2011.46.45.png)


그리고는 `fs:[0x30]` 에 접근하여 **Process Environment Block**을 가져와 `kernel32.dll`에 존재하는 `GetProcAddress` 함수의 맵핑된 주소를 가져옵니다.

![pic10](./pic/스크린샷%202020-12-20%20오후%2011.51.04.png)


이후 `GetProcAddress`함수를 통해 악성코드 내부에서 사용할 함수의 맵핑된 주소를 가져옵니다. 

이 자식, 생각보다 착한 놈이였습니다. 가져오는 함수를 해시화 시키지 않다니.. 하마터면 스크립트를 짜야하는줄 알고 긴장했습니다..

### 16바이트 데이터 복호화

![pic11](./pic/스크린샷%202020-12-20%20오후%2011.54.03.png)

다음 행위를 보니... 맨 처음에 넣어준 인자를 통해서 뭔가 가져와 16byte 만큼 복호화를 하는거 같네요 뭔가 장난질을 하는군요! 잠시 착한놈이라고 생각한 제가 바보였습니다.. 하아..🤦🏻‍♂️

![pic12](./pic/스크린샷%202020-12-21%20오전%2012.00.57.png)

### 큰 데이터 복호화

일단 복호화 코드를 제작하기 전에 전체 기능부터 크게 둘러 보고 제작하겠습니다.

위에서 복호화된 16byte값을 알아 내기 위해 다음 복호화 코드를 보니 16byte짜리 구조체인것을 알 수 있었습니다. 

```c++
  // 데이터 복호화 2번째 (위에 캡처코드 아래있는 코드입니다.)
  size = dec_16buf_size + 16;
  dec_buf = VirtualAlloc(0, dec_16buf_size + 16, 4096, 4);
  if ( !dec_buf )
    return (int **)&loc_B;
  v22 = keyinit;
  v23 = keyinit;
  key3 = keyinit;
  key4 = keyinit;
  if ( size > 0 )
  {
    v24 = (_BYTE *)dec_buf;
    key2_tmp = (int)_0Ah - dec_buf;
    do
    {
      v22 = v22 + (v22 >> 3) - 0x11111111;
      v23 = v23 + (v23 >> 5) - 0x22222222;
      key3 += 0x33333333 - (key3 << 7);
      key4 += 0x44444444 - (key4 << 9);
      *v24 = v24[key2_tmp] ^ (key4 + key3 + v23 + v22);
      ++v24;
      --size;
    }
    while ( size );
  }
```

즉 16바이트 만큼 복호화된 데이터는 아래와 같은 구조체를 가집니다.

```c++
  char keyinit[4]; // [esp+8h] [ebp-100h] BYREF
  int unkown_compare_pattern; // [esp+Ch] [ebp-FCh]
  int unkown2_compare_pattern; // [esp+10h] [ebp-F8h]
  int dec_16buf_size; // [esp+14h] [ebp-F4h]
```

이후 복호화된 큰 데이터를 `RtlDecompressBuffer` 압축 해제를 해줍니다. 아래 코드(제대로 복호화 되었는지 PE구조 확인)를 볼 때 복호화된 큰 데이터는 추가 악성코드인것 같습니다. 

![pic13](./pic/스크린샷%202020-12-21%20오전%2012.31.58.png)

복호화 행위 이후에는 밑장 깔기로 넣은 인자와 함께 메모리에 로드된 후 실행 됩니다.

### 복호화 코드

복호화 코드 제작하면서 데이터 날려먹으면 복원이 어렵습니다.. 

IDA 7.5 버전에서는 `Ctrl-Z` 기능이 가능한데, 지금 깔려있는 버전이 7.2 버전이라 귀찮은 관계로 `C4164EFA57204AD32AEC2B0F1A12BB3A` 해시에서 `Segment`를 생성해서 작업 했습니다.

```python
from idaapi import *
from idautils import *
from idc import *
from struct import unpack, pack
import lznt1

def read_shellcode(base):
    with open("license.rtf", "rb") as p:
        data = p.read()
    size = len(data)
    add_segm(0, base, base + size, "CODE", "CODE")
    patch_bytes(base, data)

def decrypt(base, size):
    tmpkey = get_dword(base)
    key1 = key2 = key3 = key4 = tmpkey
    ea = base
    data = bytearray(get_bytes(ea, size))
    for i in range(size):
        key1 = key1 + (key1 >> 3) - 0x11111111
        key1 &= 0xffffffff
        key2 = key2 + (key2 >> 5) - 0x22222222
        key2 &= 0xffffffff
        key3 += 0x33333333 - (key3 << 7)
        key3 &= 0xffffffff
        key4 += 0x44444444 - (key4 << 9)
        key4 &= 0xffffffff
        data[i] = (data[i] ^ (key1 + key2 + key3 + key4))&0xff
    return bytes(data)
    
if __name__ == "__main__":
    base = 0x41410000
    read_shellcode(base)
    struct = decrypt(base+0xa, 16)
    size = unpack("<L", struct[12:16])[0] + 16
    
    data = bytes(decrypt(base+0xa, size)[16:])
    decompressed = lznt1.decompress(data)
    
    stage2_base = 0x42420000
    add_segm(0, stage2_base, stage2_base + len(decompressed), "CODE", "CODE")
    patch_bytes(stage2_base, decompressed)
    with open("dump.bin", "wb") as p:
        p.write(decompressed)
    print("base addr: 0x%x, size: %d, newbase: 0x%x"%(base, size,stage2_base))
```
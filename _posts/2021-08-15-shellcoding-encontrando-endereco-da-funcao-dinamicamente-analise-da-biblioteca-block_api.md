---
layout: post
title: 'Shellcoding - Encontrando endereço da função dinamicamente. Análise da biblioteca block_api'
date: 2021-08-15 16:26:52.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Criação de Exploits
- Offensive Security
tags:
- Offensive Security
- Buffer Overflow
- Shellcoding
- OSED
- OSEE
- OSCE3
- Pentest
- Criação de Exploits
- Windows Internals
author: Helvio Junior (m4v3r1ck)
permalink: '/it/security/criacao-de-exploits/shellcoding-encontrando-endereco-da-funcao-dinamicamente-analise-da-biblioteca-block_api/'
excerpt: "Neste artigo iremos dissecar a biblioteca da Metasploit chamada Block API responsável por localizar em tempo de execução o endereço das funções dentro dos módulos carregados na aplicação."
---

Introdução
----------

Neste artigo iremos dissecar a biblioteca da Metasploit chamada Block API responsável por localizar em tempo de execução o endereço das funções dentro dos módulos carregados na aplicação.

Porém, antes de entrarmos efetivamente no assunto deste post é interessante conceituar algumas coisas: A primeira delas é sobre o termo Shellcoding.

Shellcoding é um termo muito utilizado para designar um código escrito em assembly utilizando durante o processo de exploração de binários (Windows e Linux), seja para criação de um shell reverso, bind shell como para execução de comandos, execução de uma aplicação e etc.

Em um processo de criação de shellcoding temos a possibilidade de trabalhar com 2 estratégias, a primeira delas utilizando Syscall e a segunda utilizando APIs dos subsistemas do sistema operacional.

Arquitetura Windows e Linux
---------------------------

De forma simplificada a imagem abaixo ilustra a arquitetura do sistema operacional Linux

[![]({{site.baseurl}}/assets/2021/08/8359a0a3ce9f4b8c8645c9cedffca97e.png)]({{site.baseurl}}/assets/2021/08/8359a0a3ce9f4b8c8645c9cedffca97e.png)

Fonte: [https://infoslack.com/devops/linux-101-arquitetura](https://infoslack.com/devops/linux-101-arquitetura)

Bem como temos a figura abaixo ilustrando a arquitetura do Windows

[![]({{site.baseurl}}/assets/2021/08/36c41ddc969a4761a25396a46edbf8a3.png)]({{site.baseurl}}/assets/2021/08/36c41ddc969a4761a25396a46edbf8a3.png)

Fonte: Pavel, Y at all. Windows Internals Part 1: 1. ed. Washington: Microsoft, 2017. Pg 47

Problema do Syscall
-------------------

Como observado am ambas arquiteturas (Windows e Linux) temos 2 possibilidades de realizar chamadas para o SO, a primeira delas utilizando as bibliotecas e subsistemas do sistema operacional (glibc, kernel32.dll, user32.dll e etc...), a segunda metodologia é utilizando system calls (ou também conhecida como syscall).

Em um Linux é muito comum e fácil se utilizar as syscalls pois no Linux os IDs das syscalls não se alteram com novas releases, versões e etc, além de serem amplamente documentada. Já em um ambiente Windows não existe uma documentação oficial sobre o tema e é altamente refutado a utilização, pois a cada release do SO os ids das syscalls se alteram, desta forma um shellcode não se torna confiável.

Vale a pena ressaltar que existem técnicas para identificar os IDs da syscall e utiliza-las, mas isso fica para outro artigo.

Desta forma é muito comum em um ambiente windows os shellcodings utilizarem as funções expostas diretamente pelas APIs do windows (ou também conhecidas como subsistemas) que são a Kernel32.dll, user32.dll etc...

Para um melhor aprofundamento recomendo a visualização do vídeo do Rafael Salema falando sobre o assunto [Stop calling APIs! Demystifying direct syscall](https://www.youtube.com/watch?v=nQNxAje5SxI)

Objetivo deste artigo
---------------------

Como em shellcoding windows geralmente utilizamos as APIs do sistema operacional e estas APIs geralmente executam no sistema operacional com [Address space layout randomization - ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) de forma que a cada execução ou a cada reboot do sistema operacional, bem como a cada compilação da DLL tem-se um endereço diferente para as chamadas de funções.

Sendo assim o shellcode para ser confiável precisa deter um método de identificar dinamicamente o endereço de uma função.

Em nossos treinamentos ensinamos a utilizar as bibliotecas da Metasploit, chamadas Block API, para este fim. Bibliotecas disponíveis em:

*   **32 bits:** [https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm)
*   **64 bits:** [https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm)

> A propósito eu realizei algumas otimizações para que o ASM da versão em 64 bits não tenha nullbyte e de quebra houve uma redução de tamanho. Por questões internas e comentadas no Pull Request o mesmo não foi realizado o merge, mas para quem tiver interesse segue a referencia: [Pull Request #17934](https://github.com/rapid7/metasploit-framework/pull/17934).
{: .prompt-tip }


Inclusive temos um mini-treinamento disponível em nosso canal do Youtube sobre Shellcoding para 64 bits: [https://www.youtube.com/watch?v=ySKEF8MHcZA](https://www.youtube.com/watch?v=ySKEF8MHcZA) utilizando essa biblioteca.

O que faremos neste artigo é entender passo a passo (dissecar) o que essa biblioteca realiza, quais estruturas, tabelas e dados da aplicação ela analisa para chegar a identificar de forma precisa o endereço exato da função dentro do Windows.

Sendo assim este artigo focará somente no sistema operacional Windows.

Conceitos e referencias complementares
--------------------------------------

Durante este estudo iremos falar de diversos assuntos e daremos ênfase/aprofundamento somente naquilo que é pertinente para o nosso estudo, sendo assim para um melhor entendimento e aprofundamento recomendo a consulta aos seguintes materiais:

*   Windows PE Format: PE é o acronimo de Portable Executable, que na prática é qualquer binário executável no windows incluindo .exe, .dll. Especificações técnicas: [https://docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) e https://www.aldeid.com/wiki/PE-Portable-executable])https://www.aldeid.com/wiki/PE-Portable-executable)
*   Intel® 64 and IA-32 Architectures Software Developer Manuals: Este manual traz de forma detalhada diversas questões de desenvolvimento para Intel, mas o foco que utilizamos é para o entendimento das principais instruções Assembly utilizadas neste artigo: [https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
*   WinDBG: Neste artigo utilizaremos o WinDBG como debugger disponível em: [https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
*   [https://www.youtube.com/watch?v=ySKEF8MHcZA](https://www.youtube.com/watch?v=ySKEF8MHcZA)

> Caso não tenha familiaridade com instruções assembly, ponteiros e pilha, recomendo antes da continuidade da leitura a visualização desta aula do Youtube [https://www.youtube.com/watch?v=ySKEF8MHcZA](https://www.youtube.com/watch?v=ySKEF8MHcZA) pois nesta aula é apresentada diversos conceitos extremamente necessários para o entendimento deste artigo.
{: .prompt-warning }

Instalando WinDbg
-----------------

Para realizar a instalação do WinDBG faça o download do SDK do Windows 10 disponível em: [https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)

[![]({{site.baseurl}}/assets/2021/08/63543e7e146c45a298bd1f122c0f5ccf.png)]({{site.baseurl}}/assets/2021/08/63543e7e146c45a298bd1f122c0f5ccf.png)

Após instalado realize a configuração do local de armazenamento e download dos símbolos de debug.

Abra o WinDBG x68 e vá em File > Symbol File Path e adicione o conteúdo abaixo

```bash
srv\*c:\symbols\*c:\symbols\*http://msdl.microsoft.com/download/symbols  
```

[![]({{site.baseurl}}/assets/2021/08/8996097d1a4d4be9b6ef0fb04a5f3859.png)]({{site.baseurl}}/assets/2021/08/8996097d1a4d4be9b6ef0fb04a5f3859.png)

Carregue uma aplicação qualquer em 32 bits como

```bash
C:\Windows\SysWOW64\notepad.exe  
```

[![]({{site.baseurl}}/assets/2021/08/f50155a62904444dae9b7655288ae33f.png)]({{site.baseurl}}/assets/2021/08/f50155a62904444dae9b7655288ae33f.png)

Recarregue todos os simbolos

```bash
.reload /f  
```

[![]({{site.baseurl}}/assets/2021/08/388d8891016e4654a101bc40fb85bc0b.png)]({{site.baseurl}}/assets/2021/08/388d8891016e4654a101bc40fb85bc0b.png)

Process Internals
-----------------

Cada processo windows é representado por um bloco EPROCESS (Executive Process), o bloco EPROCESS contem uma série de apontamentos para um numero grande de outras estruturas, por exemplo ETHREADS, TEB, PED entre outras.

A Figura abaixo simplifica o diagrama das estruturas do processo e threads.

[![]({{site.baseurl}}/assets/2021/08/d817862488ea47d683756ffa2da72a85.png)]({{site.baseurl}}/assets/2021/08/d817862488ea47d683756ffa2da72a85.png)  
Fonte: Russinovich, M at all. Windows Internals: 5. ed. Washington: Microsoft, 2009. Pg 336

Para nosso estudo vale ressaltar uma tabela extremamente importante que é a TEB (Thread Environment Block), por compatibilidade também conhecida como TIB (Thread Information Block). A TEB pode ser utilizada para obter uma série de informações do processo sem a necessidade de realizar chamadas para as APIs Win32. Entre outras informações armazena o endereço do SEH e o endereço da tabela PEB (Process Environment Block), que por sua vez através da PEB pode-se obter acesso a IAT (Import Address Table) e muito mais.  
A TEB pode pode ser acessada através do registrador de segmento FS.

### Loader

No momento da inicialização do aplicativo uma série de atividades são realizadas. Na prática o loader é executado antes do código da própria aplicação de forma que o mesmo é transparente ao usuário. Dentre as atividades em que o loader é responsável iremos destacar duas que são importantes para nosso estudo:

*   Tratar a IAT (Import Address Table) da aplicação e olhar para todas as DLLs que a aplicação necessita, bem como analisar recursivamente a IAS de todas as DLLs carregadas, seguido da análise da tabela de exportação das DLLs para ter certeza que as funções desejadas estão presentes.
*   Carregar e descarregar DLLs em tempo de execução, mesmo as carregadas sobre demanda e manter a lista de todos os módulos conhecida como Módules Database ou também como LDR (Loader Data Table).

Análise da block api 32 bits
----------------------------

A biblioteca da Block API está disponível no github da Metasploit em [https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm)

### Utilização

Antes de adentrarmos a análise do código da BlockAPI vamos a um exemplo de utilização.

Neste exemplo iremos utilizar a função ExitProcess documentada em [https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)

Tendo sua sintaxe como abaixo:

```c
void ExitProcess(  
UINT uExitCode  
);  
```


#### Código C

```c
#include <Windows.h>  
#include <stdio.h>

void main(){

ExitProcess(0);

}  
```
{: file='exit.c'}

#### Hash da api

A block_api espera como entrada no topo da pilha o hash da função desejada seguido dos parâmetros da função.

Para o cálculo do hash da função utilizaremos uma aplicação desenvolvida por mim disponível em [https://github.com/helviojunior/addrfinder](https://github.com/helviojunior/addrfinder)

[![]({{site.baseurl}}/assets/2021/08/8e005921686341d4a9de29bd0d4dd1ef.png)]({{site.baseurl}}/assets/2021/08/8e005921686341d4a9de29bd0d4dd1ef.png)

Note que o hash da função **ExitProcess** é **0x56A2B5F0**, este hash não se altera mesmo em releases diferentes do windows.

#### Assembly - utilizando a block_api

```
[BITS 32]

global _start

_start:  
jmp short block_api

get_block_api:  
pop edi ; Copia o endereço da block_api no registrador edi

; Sai da aplicação sem aprentar erro  
xor eax,eax ; Zera EAX  
push eax ; Coloca na pilha o "exit code" = 0x00

; Realiza a chamada da função ExitProcess  
push 0x56A2B5F0 ; Coloca o endereço do hash função ExitProcess na pilha  
call edi ; Executa a block_api para localizar e executar a função

block_api:  
call get_block_api  
%include "../block_api.asm"  
```
{: file='exit.asm'}

[![]({{site.baseurl}}/assets/2021/08/5033fcd6f11140fcb573c532cee9d279.png)]({{site.baseurl}}/assets/2021/08/5033fcd6f11140fcb573c532cee9d279.png)

Como podemos observar no código acima na linha 22 realizamos a inclusão do arquivo da biblioteca (exatamente o mesmo arquivo listado no link do github acima)

Utilizando a estratégia de JMP; Call; POP salvamos o endereço da primeira instrução da block_api no registrador EDI

Sendo assim podemos colocar na pilha de forma que ficará como abaixo:

*   ESP + 0x00 = 0x56A2B5F0
*   ESP + 0x04 = 0x00000000

E posteriormente executamos a block_api através da instrução **call edi**

#### Montagem e executando

> Utilizaremos a aplicação `shellcodetester` desenvolvida por mim para a realização dos testes. Denso assim você pode realizar a instalação diretamente via PyPi com o comando `pip3 install shellcodetester`
{: .prompt-warning }

Para a montagem (conversão dos mnemônico ASM para binário/hexa) utilizaremos o o ShellcodeTester (Disponível em [https://github.com/helviojunior/shellcodetester](https://github.com/helviojunior/shellcodetester))

Para a instalação do mesmo basta realizar o comando 

```bash
pip3 install --upgrade shellcodetester
```

Após a instalação realize a montagem e compilação de um EXE através do comando

```bash
shellcodetester -asm exit.asm --break-point
```

Abra o Windbg e execute o arquivo gerado `st-exit.exe`

Agora na console do windbg digite o comando `go`


Análise do nosso shellcode
--------------------------

Antes de chegar efetivamente na biblioteca da block api nós temos algumas instruções das quais podemos colocar lado a lado com nosso código

[![]({{site.baseurl}}/assets/2021/08/bd6ffc8df5b345508a8b063e73cea5b3.png)]({{site.baseurl}}/assets/2021/08/bd6ffc8df5b345508a8b063e73cea5b3.png)

Como o foco é na execução da própria block_api vamos até o ponto da chamada **call edi**

Neste momento temos no registrador EDI o endereço da block_api

[![]({{site.baseurl}}/assets/2021/08/19c8531c17944b009ff8244113f6172f.png)]({{site.baseurl}}/assets/2021/08/19c8531c17944b009ff8244113f6172f.png)

E começaremos a nossa análise deste ponto

Análise da block_api
---------------------

Para facilitar o processo de análise vou colocando o código da block_api conforme formos evoluindo no mesmo.

### Tabelas

Como comentado anteriormente há uma série de tabelas existentes e utilizadas em nosso aplicativo, sendo assim segue um diagrama com o fluxo que realizaremos na próximas instruções

[![]({{site.baseurl}}/assets/2021/08/fb50b1ae0c2247498d36b0864c28432a.png)]({{site.baseurl}}/assets/2021/08/fb50b1ae0c2247498d36b0864c28432a.png)

Primeiramente utilizaremos o registrador de segmento FS em seu offset 0x30 para obter o endereço relativo (offset) de memória da tabela TEB, posteriormente pegaremos de dentro da TEB em seu offset 0x0C o endereço da tabela LDR e por fim dentro da tabela LDR pegaremos o endereço de memória do primeiro elemento da array InMemoryOrderModuleList.

### Termos de memória

#### VRA (Virtual Relative Addres)

Daqui para frente utilizaremos o termo VRA (Virtual Relative Address) este termo refere-se a um endereço de memória relativo ao Base Address (ou também conhecido como Offset), de forma que o offset de uma DLL só se altera se houver a recompilação da mesma, o que o ASLR interfere é no BaseAddress, este sim se altera a cada reboot da maquina ou a cada execução da aplicação.

#### VMA (Virtual Memory Address)

O VMA é igual ao VRA + BaseAddress, ou seja o endereço virtual que pode ser utilizado dentro da aplicação.

### Função api_call

Segue abaixo o trecho de código da primeira função api_call

```bash
api_call:  
pushad ; We preserve all the registers for the caller, bar EAX and ECX.  
mov ebp, esp ; Create a new stack frame  
xor edx, edx ; Zero EDX  
mov edx, [fs:edx+0x30] ; Get a pointer to the PEB  
mov edx, [edx+0xc] ; Get PEB->Ldr  
mov edx, [edx+0x14] ; Get the first module from the InMemoryOrder module list  
```

#### pushad

Pushad é uma instrução que coloca na pilha todos os registradores, em outras palavras, salva o valor de todos os registradores na pilha. Este processo consome 20 bytes da pilha

#### mov ebp, esp

Copia o endereço do topo da pilha para ebp. Este processo é conhecido como prólogo de uma função, ou seja, está igualando ESP e EBP para iniciar um novo **stack frame**

#### xor edx, edx

A operação matematica XOR de um valor com ele mesmo sempre resultará em Zero, sendo assim esta instrução zera o valor do registrador EDX

#### mov edx, [fs:edx+0x30]

Copia o VRA da PEB para dentro do registrador EDX

Dentro do windbg podemos visualizar essa informação com o comando abaixo

```txt
0:009> dt nt!_TEB @$teb  
ntdll!_TEB  
+0x000 NtTib : _NT_TIB  
+0x01c EnvironmentPointer : (null)  
+0x020 ClientId : _CLIENT_ID  
+0x028 ActiveRpcHandle : (null)  
+0x02c ThreadLocalStoragePointer : 0x0146a988 Void  
+0x030 ProcessEnvironmentBlock : 0x010da000 _PEB  
+0x034 LastErrorValue : 0  
+0x038 CountOfOwnedCriticalSections : 0  
+0x03c CsrClientThread : (null)  
+0x040 Win32ThreadInfo : (null)  
+0x044 User32Reserved : [26] 0  
+0x0ac UserReserved : [5] 0  
+0x0c0 WOW32Reserved : 0x77c16000 Void  
+0x0c4 CurrentLocale : 0x409  
+0x0c8 FpSoftwareStatusRegister : 0  
+0x0cc ReservedForDebuggerInstrumentation : [16] (null)  
+0x10c SystemReserved1 : [26] (null)  
+0x174 PlaceholderCompatibilityMode : 0 ''  
+0x175 PlaceholderHydrationAlwaysExplicit : 0 ''  
+0x176 PlaceholderReserved : [10] ""  
+0x180 ProxiedProcessId : 0  
```

E confirmando a informação após a execução da instrução

[![]({{site.baseurl}}/assets/2021/08/21769f1837a241d0b7dcf1cc39f28526.png)]({{site.baseurl}}/assets/2021/08/21769f1837a241d0b7dcf1cc39f28526.png)

#### mov edx, [edx+0xc]

Copia o VRA da LDR para dentro do registrador EDX

```txt
0:009> dt nt!_PEB 0x010da000  
ntdll!_PEB  
+0x000 InheritedAddressSpace : 0 ''  
+0x001 ReadImageFileExecOptions : 0 ''  
+0x002 BeingDebugged : 0x1 ''  
+0x003 BitField : 0 ''  
+0x003 ImageUsesLargePages : 0y0  
+0x003 IsProtectedProcess : 0y0  
+0x003 IsImageDynamicallyRelocated : 0y0  
+0x003 SkipPatchingUser32Forwarders : 0y0  
+0x003 IsPackagedProcess : 0y0  
+0x003 IsAppContainer : 0y0  
+0x003 IsProtectedProcessLight : 0y0  
+0x003 IsLongPathAwareProcess : 0y0  
+0x004 Mutant : 0xffffffff Void  
+0x008 ImageBaseAddress : 0x00f40000 Void  
+0x00c Ldr : 0x77d40c40 _PEB_LDR_DATA  
+0x010 ProcessParameters : 0x013d19d0 _RTL_USER_PROCESS_PARAMETERS  
+0x014 SubSystemData : (null)  
+0x018 ProcessHeap : 0x013d0000 Void  
+0x01c FastPebLock : 0x77d409e0 _RTL_CRITICAL_SECTION  
+0x020 AtlThunkSListPtr : (null)  
+0x024 IFEOKey : (null)  
+0x028 CrossProcessFlags : 9  
+0x028 ProcessInJob : 0y1  
+0x028 ProcessInitializing : 0y0  
```

[![]({{site.baseurl}}/assets/2021/08/637cc9ff49334ee78bcf36a095d040ea.png)]({{site.baseurl}}/assets/2021/08/637cc9ff49334ee78bcf36a095d040ea.png)

#### mov edx, [edx+0x14]

Copia o VRA do primeiro elemento da array **InMemoryOrderModuleList** da tabela LDR para o registrador EDX.

```txt
0:009> dt _PEB_LDR_DATA 0x77d40c40  
ntdll!_PEB_LDR_DATA  
+0x000 Length : 0x30  
+0x004 Initialized : 0x1 ''  
+0x008 SsHandle : (null)  
+0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x13d32a0 - 0x140d710 ]  
+0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x13d32a8 - 0x140d718 ]  
+0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x13d31c8 - 0x140d670 ]  
+0x024 EntryInProgress : (null)  
+0x028 ShutdownInProgress : 0 ''  
+0x02c ShutdownThreadId : (null)  
```

[![]({{site.baseurl}}/assets/2021/08/8d5afbd757e84622bee6ac7587f5d806.png)]({{site.baseurl}}/assets/2021/08/8d5afbd757e84622bee6ac7587f5d806.png)

Neste ponto temos em **EDX** o VRA do primeiro elemento da lista duplamente encadeada **InMemoryOrderModuleList**.

[![]({{site.baseurl}}/assets/2021/08/263625546a4046e3b33d92971fae19ea.png)]({{site.baseurl}}/assets/2021/08/263625546a4046e3b33d92971fae19ea.png)

```txt
0:009> dt _LIST_ENTRY (0x77d40c40 + 0x14)  
ntdll!_LIST_ENTRY  
[ 0x13d32a8 - 0x140d718 ]  
+0x000 Flink : 0x013d32a8 _LIST_ENTRY [ 0x13d31c0 - 0x77d40c54 ]  
+0x004 Blink : 0x0140d718 _LIST_ENTRY [ 0x77d40c54 - 0x140d878 ]

```

Essa informação não parece muito útil, mas conforme podemos visualizar na documentação ([https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)) a estrutura LIST_ENTRY faz parte de uma estrutura maior chamada `_LDR_DATA_TABLE_ENTRY`

```txt
typedef struct _LIST_ENTRY {  
struct _LIST_ENTRY \*Flink;  
struct _LIST_ENTRY \*Blink;  
} LIST_ENTRY, \*PLIST_ENTRY, \*RESTRICTED_POINTER PRLIST_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY {  
PVOID Reserved1[2];  
LIST_ENTRY InMemoryOrderLinks;  
PVOID Reserved2[2];  
PVOID DllBase;  
PVOID EntryPoint;  
PVOID Reserved3;  
UNICODE_STRING FullDllName;  
BYTE Reserved4[8];  
PVOID Reserved5[3];  
union {  
ULONG CheckSum;  
PVOID Reserved6;  
};  
ULONG TimeDateStamp;  
} LDR_DATA_TABLE_ENTRY, \*PLDR_DATA_TABLE_ENTRY;  
```

Para realizar o dump da estrutura temos de subtrair 0x08 do endereço da `_LIST_ENTRY` com o objetivo de encontrar o início da estrutura `_LDR_DATA_TABLE_ENTRY`

```txt
0:009> dt _LDR_DATA_TABLE_ENTRY (013d32a8 - 0x8)  
ntdll!_LDR_DATA_TABLE_ENTRY  
+0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x13d31b8 - 0x77d40c4c ]  
+0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x13d31c0 - 0x77d40c54 ]  
+0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x0 - 0x0 ]  
+0x018 DllBase : 0x00f40000 Void  
+0x01c EntryPoint : (null)  
+0x020 SizeOfImage : 0xa2000  
+0x024 FullDllName : _UNICODE_STRING "C:\Tools\ShellcodeTester\Runner.exe"  
+0x02c BaseDllName : _UNICODE_STRING "Runner.exe"  
+0x034 FlagGroup : [4] "???"  
+0x034 Flags : 0x14022c4  
```

[![]({{site.baseurl}}/assets/2021/08/d7bfcd1e25424cdfa2e17772de1c8dd2.png)]({{site.baseurl}}/assets/2021/08/d7bfcd1e25424cdfa2e17772de1c8dd2.png)

### Função next_mod

```
next_mod: ;  
mov esi, [edx+0x28] ; Get pointer to modules name (unicode string)  
movzx ecx, word [edx+0x26] ; Set ECX to the length we want to check  
xor edi, edi ; Clear EDI which will store the hash of the module name  
```

#### mov esi, [edx+0x28]

Copia o VMA do nome do módulo

```txt
0:009> du @esi  
013d1eb6 "Runner.exe"  
```

[![]({{site.baseurl}}/assets/2021/08/8a5a33bf66554437b4d62050bd0ffcf8.png)]({{site.baseurl}}/assets/2021/08/8a5a33bf66554437b4d62050bd0ffcf8.png)

#### movzx ecx, word [edx+0x26]

Recupera o tamanho do nome do módulo, lembrando que cada caractere em unicode corresponde a 2 bytes e temos mais os 2 null bytes no final

Em nosso cenário:

*   Runner.exe = 10 Caracteres + 1 null byte
*   11 \* 2 = 22

[![]({{site.baseurl}}/assets/2021/08/3339f66e40354ec6bcf91b0dc4c6335e.png)]({{site.baseurl}}/assets/2021/08/3339f66e40354ec6bcf91b0dc4c6335e.png)

#### xor edi, edi

Zera o EDI para utilizar como local de armazenamento do hash do nome do módulo

### Função loop_modname

```
loop_modname: ;  
xor eax, eax ; Clear EAX  
lodsb ; Read in the next byte of the name  
cmp al, 'a' ; Some versions of Windows use lower case module names  
jl not_lowercase ;  
sub al, 0x20 ; If so normalise to uppercase  
```

#### xor eax, eax

Zera EAX

#### lodsb

Carrega o primeiro byte vindo do ESI para o registrador AL.

#### cmp al, 'a'

Compara o byte recebido com o caractere 'a'

#### jl not_lowercase

Antes de vermos a comparação propriamente dita vamos analisar a tabela ASCII

[![]({{site.baseurl}}/assets/2021/08/1c806d639e2e4ce89a3fa1bc9a6c2bae.png)]({{site.baseurl}}/assets/2021/08/1c806d639e2e4ce89a3fa1bc9a6c2bae.png)

Observe na tabela ASCII que o alfabeto minúsculo vai do hexa-decimal 0x61 até 0x7a e o maiúsculo vai de 0x41 a 0x5a, então:

*   O minúsculo é exatamente 0x20 bytes que sua representação em maiúsculo
*   O hexa-decimal do caractere em minúsculo é maior que sua representação em maúsculo

A instrução JL (Jump Short if less) verifica se o caractere em questão é menor que o caractere 'a', considerando que os valores em decimal/hexa-decimal dos caracteres em maiúsculo são menores que os em minúsculo, se sim o caractere é maiúsculo, neste cenário salta para a função **not_lowercase**

#### sub al, 0x20

Caso o caractere seja minúsculo, basta subtratir 0x20 que ele se tornará maiúsculo

### Função not_lowercase

Esta é uma função grande que na verdade realiza as seguintes operaçÕes:

*   Cálculo do hash do nome do módulo
*   Resgata uma série de informações do módulo (Base Address, índice na lista, tabela de exports, número de funções, tabela de nomes da funções)

Desta forma iremos analisar parte por parte dessa função (em pequenos códigos)

```
not_lowercase: ;  
ror edi, 0xd ; Rotate right our hash value  
add edi, eax ; Add the next byte of the name  
dec ecx  
jnz loop_modname ; Loop until we have read enough  
; We now have the module hash computed  
push edx ; Save the current position in the module list for later  
push edi ; Save the current module hash for later  
```

#### ror edi, 0xd

Rotaciona 0xd (decimal, 13) bits para a direita do valor presente no EDI (Hash Value)

#### add edi, eax

Adiciona o byte (resgatado do nome da função) ao valor presente no EDI e salva o resultado no próprio EDI

#### dec ecx

Decrementa o ECX (nosso contador)

#### jnz loop_modname

Jump short if not zero, verifica se o resultado da ultima operação matemática é diferente de zero, ou seja, irá saltar para a função **loop_modname** enquanto o ECX for maior que zero

#### push edx

Salva na pilha o valor de EDX que neste momento representa o índice do módulo na tabela LDR.InMemoryOrderModuleList

#### push edi

Salva na pilha o hash do nome do módulo atual

### Função not_lowercase - parte 2

Essa fase da função irá buscar as informações das funções exportadas de dentro do módulo atual.

```
; Proceed to iterate the export address table,  
mov edx, [edx+0x10] ; Get this modules base address  
mov eax, [edx+0x3c] ; Get PE header  
add eax, edx ; Add the modules base address  
mov eax, [eax+0x78] ; Get export tables RVA  
test eax, eax ; Test if no export address table is present  
jz get_next_mod1 ; If no EAT present, process the next module  
add eax, edx ; Add the modules base address  
push eax ; Save the current modules EAT  
mov ecx, [eax+0x18] ; Get the number of function names  
mov ebx, [eax+0x20] ; Get the rva of the function names  
add ebx, edx ; Add the modules base address  
```

#### mov edx, [edx+0x10]

Neste momento ainda temos no EDX o endereço da estrutura `_LIST_ENTRY` do módulo atual, sendo assim em seu offset 0x10 tem-se o BaseAddress do módulo, desta forma esta instrução copia o BaseAddress do módulo que está sendo analisado para o Registrador EDX

[![]({{site.baseurl}}/assets/2021/08/472981a7d03842059a6aa08dc1264726.png)]({{site.baseurl}}/assets/2021/08/472981a7d03842059a6aa08dc1264726.png)

Note que para realizar o parse da estrutura `_LDR_DATA_TABLE_ENTRY` temos de subtrair 0x08, então o Offset que aparece na imagem é 0x18, ou seja 0x10 + 0x08. Onde temos o valor 0x00f40000

Valor este que podemos confirma de mais outros 2 modos

[![]({{site.baseurl}}/assets/2021/08/b5d48cd0bece439d8eca9dad186b0dfc.png)]({{site.baseurl}}/assets/2021/08/b5d48cd0bece439d8eca9dad186b0dfc.png)

```txt
0:009> dd @edx + 10  
013d32b8 00f40000 00000000 000a2000 00480046  
013d32c8 013d1e84 00160014 013d1eb6 014022c4  
013d32d8 0000ffff 77d40ac0 013d31f4 5f125ed8  
013d32e8 00000000 00000000 013d3350 013d3350  
013d32f8 013d3350 00000000 00000000 00000000  
013d3308 00000000 00000000 0140d099 013d4f64  
013d3318 013d38c4 00000000 00400000 00000000  
013d3328 11fb4e0f 01d79199 10078c54 00000004

0:009> lm m runner  
Browse full module list  
start end module name  
00f40000 00fe2000 Runner C (no symbols)  
```

Neste momento temos em EDX o BaseAddress do módulo que está sendo verificado.

### Binary internals

Para facilitar o entendimento vamos adentrar nas tabelas que iremos resgatar as informações

[![]({{site.baseurl}}/assets/2021/08/b9a2470b34804531b292d9276ac26780.png)]({{site.baseurl}}/assets/2021/08/b9a2470b34804531b292d9276ac26780.png)

#### MS-DOS PE HEader

https://www.aldeid.com/wiki/PE-Portable-executable

[![]({{site.baseurl}}/assets/2021/08/76ca63c41bf6481e9884ffd78bc9730a.png)]({{site.baseurl}}/assets/2021/08/76ca63c41bf6481e9884ffd78bc9730a.png)

#### PE HEader

BaseAssress + 0x3c = Início do PE Header

[![]({{site.baseurl}}/assets/2021/08/5fa512a8337a42f2a2a48f2b29147736.png)]({{site.baseurl}}/assets/2021/08/5fa512a8337a42f2a2a48f2b29147736.png)

[![]({{site.baseurl}}/assets/2021/08/6fee8b530ed94e9e8f3a7060f0883a51.png)]({{site.baseurl}}/assets/2021/08/6fee8b530ed94e9e8f3a7060f0883a51.png)

#### Export Table

[https://www.aldeid.com/wiki/PE-Portable-executable#Export_Table](https://www.aldeid.com/wiki/PE-Portable-executable#Export_Table)

A tabela de exports está no offset 0x78 a partir do início do PE Header. Cada módulo (Executável/DLL) conterá o seu próprio PE Header e consequentemente a sua tabela de exportação.

[![]({{site.baseurl}}/assets/2021/08/e65af62396474ecaa86ea23feaade247.png)]({{site.baseurl}}/assets/2021/08/e65af62396474ecaa86ea23feaade247.png)

### Função not_lowercase - parte 2 continuação

Temos na imagem o parse dos dados da DOS_HEADER

```txt
0:009> dt ntdll!_IMAGE_DOS_HEADER 00f40000  
+0x000 e_magic : 0x5a4d  
+0x002 e_cblp : 0x90  
+0x004 e_cp : 3  
+0x006 e_crlc : 0  
+0x008 e_cparhdr : 4  
+0x00a e_minalloc : 0  
+0x00c e_maxalloc : 0xffff  
+0x00e e_ss : 0  
+0x010 e_sp : 0xb8  
+0x012 e_csum : 0  
+0x014 e_ip : 0  
+0x016 e_cs : 0  
+0x018 e_lfarlc : 0x40  
+0x01a e_ovno : 0  
+0x01c e_res : [4] 0  
+0x024 e_oemid : 0  
+0x026 e_oeminfo : 0  
+0x028 e_res2 : [10] 0  
+0x03c e_lfanew : 0n128  
0:009> ? 0n128  
Evaluate expression: 128 = 00000080  
```

[![]({{site.baseurl}}/assets/2021/08/c1869b05a5bd4058856189c64a200c77.png)]({{site.baseurl}}/assets/2021/08/c1869b05a5bd4058856189c64a200c77.png)

#### mov eax, [edx+0x3c]

Copia RVA do PE Header para o registrador EAX

[![]({{site.baseurl}}/assets/2021/08/c0c2939453d0432caaa0e6df186057a5.png)]({{site.baseurl}}/assets/2021/08/c0c2939453d0432caaa0e6df186057a5.png)

Podemos observar que o EAX teve seu valor definido como 0x80, ou seja o PE Header está em Base Address + 0x80 como vemos no output abaixo

```txt
0:009> dt ntdll!_IMAGE_NT_HEADERS 00f40000 + 0x80  
+0x000 Signature : 0x4550  
+0x004 FileHeader : _IMAGE_FILE_HEADER  
+0x018 OptionalHeader : _IMAGE_OPTIONAL_HEADER  
```

[![]({{site.baseurl}}/assets/2021/08/cd76b4aa6eda47228e542fa09a92e7d7.png)]({{site.baseurl}}/assets/2021/08/cd76b4aa6eda47228e542fa09a92e7d7.png)

Adicionalmente podemos observar os cabeçalhos adicionais no Offset 0x80 em relação ao PE Header

```txt
0:009> dt ntdll!_IMAGE_OPTIONAL_HEADER 00f40000 + 0x80 + 0x18  
+0x000 Magic : 0x10b  
+0x002 MajorLinkerVersion : 0x30 '0'  
+0x003 MinorLinkerVersion : 0 ''  
+0x004 SizeOfCode : 0x51e00  
+0x008 SizeOfInitializedData : 0x4b800  
+0x00c SizeOfUninitializedData : 0  
+0x010 AddressOfEntryPoint : 0x53cf2  
+0x014 BaseOfCode : 0x2000  
+0x018 BaseOfData : 0x54000  
+0x01c ImageBase : 0x400000  
+0x020 SectionAlignment : 0x2000  
+0x024 FileAlignment : 0x200  
+0x028 MajorOperatingSystemVersion : 4  
+0x02a MinorOperatingSystemVersion : 0  
+0x02c MajorImageVersion : 0  
+0x02e MinorImageVersion : 0  
+0x030 MajorSubsystemVersion : 4  
+0x032 MinorSubsystemVersion : 0  
+0x034 Win32VersionValue : 0  
+0x038 SizeOfImage : 0xa2000  
+0x03c SizeOfHeaders : 0x200  
+0x040 CheckSum : 0  
+0x044 Subsystem : 2  
+0x046 DllCharacteristics : 0x8540  
+0x048 SizeOfStackReserve : 0x100000  
+0x04c SizeOfStackCommit : 0x1000  
+0x050 SizeOfHeapReserve : 0x100000  
+0x054 SizeOfHeapCommit : 0x1000  
+0x058 LoaderFlags : 0  
+0x05c NumberOfRvaAndSizes : 0x10  
+0x060 DataDirectory : [16] _IMAGE_DATA_DIRECTORY  
```

[![]({{site.baseurl}}/assets/2021/08/9eb697ab4e664ea6b9b9e8e19f93a37b.png)]({{site.baseurl}}/assets/2021/08/9eb697ab4e664ea6b9b9e8e19f93a37b.png)

Dentro dos cabeçalhos adicionais podemos encontrar que a Export table (DataDirectory) encontra-se no Offset 0x60 relativo aos cabeçalhos adicionais.

Desta forma se considerarmos que os cabeçalhos adicionais estão em 0x18 em relação ao PE Heder podemos então inferir que com relação ao PE Header a Exporta table está (0x18 + 0x60) = 0x78

#### add eax, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA do PE Header e o salva no registrador EAX

#### mov eax, [eax+0x78]

Copia o RVA da tabela de exports para o registrador EAX

[![]({{site.baseurl}}/assets/2021/08/c4da462e06744a94b3d1e2ead1bc3d1d.png)]({{site.baseurl}}/assets/2021/08/c4da462e06744a94b3d1e2ead1bc3d1d.png)

Como pode-se observar este é um cenário onde o módulo atual não detém nenhuma função exportada. Sendo assim iremos adicionar um breakpoint neste ponto do código para podermos executar o código até que chegue no módulo desejado. Como a função exitprocess está dentro do módulo kernel32.dll vamos executar o código até chegar neste ponto dentro do módulo kernel32.dll.

[![]({{site.baseurl}}/assets/2021/08/711ed42a3fd44518960877bcbb2f48bb.png)]({{site.baseurl}}/assets/2021/08/711ed42a3fd44518960877bcbb2f48bb.png)

Note que agora vamos executar o comando g, e a execução segue até nosso breakpoint, posteriormente podemos inspecionar qual é o módulo que estamos tratando com o comando **lm a @edx** uma vez que temos em ECX o BaseAddress do módulo atual

[![]({{site.baseurl}}/assets/2021/08/7997667cafec4e4e88a171ae43c7f922.png)]({{site.baseurl}}/assets/2021/08/7997667cafec4e4e88a171ae43c7f922.png)

Uma vez que chegamos a kernel32.dll, podemos continuar a verificação.

[![]({{site.baseurl}}/assets/2021/08/08564e0c70724f328f260baea7f34fdc.png)]({{site.baseurl}}/assets/2021/08/08564e0c70724f328f260baea7f34fdc.png)

#### test eax, eax

Verifica se há uma tabela de exports

Existe a tabela, ou seja EAX é diferente de zero, então o JMP não vai ocorrer.

#### jz get_next_mod1

Jump near if 0, verifica se o resultado da ultima operação matemática foi zero, se sim, realiza o salto. De forma que verificará se não há tabela de exports salta para a função get_next_mod1, caso contrário continua para a proxima instrução

[![]({{site.baseurl}}/assets/2021/08/bd1ee4dbb0494fb397452b53f7fc56f2.png)]({{site.baseurl}}/assets/2021/08/bd1ee4dbb0494fb397452b53f7fc56f2.png)

#### add eax, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA da tabela de exportação e o salva no registrador EAX

[![]({{site.baseurl}}/assets/2021/08/ddbd3d34d7754dc7bf6da2911c34a0fb.png)]({{site.baseurl}}/assets/2021/08/ddbd3d34d7754dc7bf6da2911c34a0fb.png)

#### push eax

Salva na pilha o VMA da tabela de exports do módulo atual

[![]({{site.baseurl}}/assets/2021/08/31d074c5b9c94b2a806bd8d6a78728a7.png)]({{site.baseurl}}/assets/2021/08/31d074c5b9c94b2a806bd8d6a78728a7.png)

#### mov ecx, [eax+0x18]

Uma vez que temos em EAX o VMA da tabela de exporta copia o número de funções exportadas para o registrador ECX

[![]({{site.baseurl}}/assets/2021/08/8dc9a7d1e4e747d0b5d0e5610294ff3b.png)]({{site.baseurl}}/assets/2021/08/8dc9a7d1e4e747d0b5d0e5610294ff3b.png)

[![]({{site.baseurl}}/assets/2021/08/9db1702461b648c2b5b3f05eec7b2304.png)]({{site.baseurl}}/assets/2021/08/9db1702461b648c2b5b3f05eec7b2304.png)

#### mov ebx, [eax+0x20]

Copia o RVA do array com o nome das funções exportadas (AddressOfNames) para o registrador EBX

#### add ebx, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA do array contendo o nome de todas as funções exportadas pelo módulo atual e o salva no registrador EBX

Neste momento temos em EBX o endereço de memória com o nome da primeira função

### Função get_next_func

```
; Computing the module hash + function hash  
get_next_func: ;  
test ecx, ecx ; Changed from jecxz to accomodate the larger offset produced by random jmps below  
jz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module  
dec ecx ; Decrement the function name counter  
mov esi, [ebx+ecx\*4] ; Get rva of next module name  
add esi, edx ; Add the modules base address  
xor edi, edi ; Clear EDI which will store the hash of the function name  
```

#### test ecx, ecx

Realiza uma verificação entre ECX e ECX

#### jz get_next_mod

Jump near if 0, salta para a função get_next_mod caso o resultado da ultima operação matematica seja zero, ou seja, caso ECX (que é nosso contador de funções) tenha chegado a zero, salta para o ponto de código responsável por iniciar o processo de verificação do próximo módulo. Caso seja ECX maior que zero, continua a execução para a proxima instrução.

[![]({{site.baseurl}}/assets/2021/08/9cf736a54e064aefbb9720a26e91121a.png)]({{site.baseurl}}/assets/2021/08/9cf736a54e064aefbb9720a26e91121a.png)

ECX diferente de zero, então o JMP não irá ocorrer

#### dec ecx

Decrementa 01 de ECX

#### mov esi, [ebx + ecx * 4]

Resgata o RVA do nome da função. Onde:

* EBX: Contém o VMA do início da array que detém o nome das funções  
* ECX: índice numérico dentro da função  
* ECX * 4: índico numérico multiplicado por 4 Bytes (32 bits) que representa cada endereço que contém o nome da função

#### add esi, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA da do nome da função e o salva no registrador EAX

[![]({{site.baseurl}}/assets/2021/08/41dad8cb4ece46e8932b9dc629527137.png)]({{site.baseurl}}/assets/2021/08/41dad8cb4ece46e8932b9dc629527137.png)

Como no decorrer dest loop iremos decrementando o ECX, na pratica vamos varrendo a lista de traz p/ frente, sendo assim na primeira intereção tremos o nome da última função do array.

[![]({{site.baseurl}}/assets/2021/08/60bfdfab2d57477d884782fe7b53e6dd.png)]({{site.baseurl}}/assets/2021/08/60bfdfab2d57477d884782fe7b53e6dd.png)

[![]({{site.baseurl}}/assets/2021/08/a82745678fc44ebbb9b3b9a943b6db86.png)]({{site.baseurl}}/assets/2021/08/a82745678fc44ebbb9b3b9a943b6db86.png)

#### xor edi, edi

Zera o registrador EDI para utiliza-lo como armazenamento do hash da função

### Função loop_funcname

```txt
loop_funcname: ;  
xor eax, eax ; Clear EAX  
lodsb ; Read in the next byte of the ASCII function name  
ror edi, 0xd ; Rotate right our hash value  
add edi, eax ; Add the next byte of the name  
cmp al, ah ; Compare AL (the next byte from the name) to AH (null)  
jne loop_funcname ; If we have not reached the null terminator, continue  
add edi, [ebp-8] ; Add the current module hash to the function hash  
cmp edi, [ebp+0x24] ; Compare the hash to the one we are searchnig for  
jnz get_next_func ; Go compute the next function hash if we have not found it  
; If found, fix up stack, call the function and then value else compute the next one...  
pop eax ; Restore the current modules EAT  
mov ebx, [eax+0x24] ; Get the ordinal table rva  
add ebx, edx ; Add the modules base address  
mov cx, [ebx+2\*ecx] ; Get the desired functions ordinal  
mov ebx, [eax+0x1c] ; Get the function addresses table rva  
add ebx, edx ; Add the modules base address  
mov eax, [ebx+4\*ecx] ; Get the desired functions RVA  
add eax, edx ; Add the modules base address to get the functions actual VA  
```

#### xor eax, eax

Zera o registrador EAX

#### lodsb

Carrega o primeiro byte vindo do ESI para o registrador AL.

#### ror edi, 0xd

Rotaciona 0xd (decimal, 13) bits para a direita do valor presente no EDI (Hash Value)

#### add edi, eax

Adiciona o byte (resgatado do nome da função) ao valor presente no EDI e salva o resultado no próprio EDI

#### cmp al, ah

Compara o byte copiado pela função lodsb salvo em AL com o registrador AH (que neste cenário será zero)

#### jne loop_funcname

Jump near if not equal, verifica se o resultado da última comparação não é iguial, ou seja, se o último byte copiado em AL é diferente de zero, caso seja diferente de zero retorna para o início da função loop_funcname para continuar copiando os bytes do nome da função e assim calculando o hash. Caso tenha chegado no terminador de string \0 (NULL Byte) continua para a próxima instrução

#### add edi, [ebp-8]

Soma o hash do nome da função recem cálculada com o hash do nome do módulo calculado anteriormente e salvo em ebp-8, salvando o resultado no registrador EDI

#### cmp edi, [ebp+0x24]

Compara se o hash cálculado é igual ao hash desejado. Onde:  
* EDI: Hash cálculado com o nome do módulo + Nome da função  
* EBP + 0x24: Posição da memória que detém o Hash da função desejada. Em nosso exemplo, este Hash foi adicionado na pilha com o PUSH 0x56A2B5F0 que é o hash da função ExitProcess

[![]({{site.baseurl}}/assets/2021/08/1eb1b42fa6714ad58a8e3e811f1f27db.png)]({{site.baseurl}}/assets/2021/08/1eb1b42fa6714ad58a8e3e811f1f27db.png)

Vamos então colocar um breakpoint nessa função para verificar após o cálculo do hash do nome de cada função + o hash do módulo, tendo então o hash final da função para posteriormente poder verificar se é igual ao desejado.

[![]({{site.baseurl}}/assets/2021/08/0e00a89fcb68481aad7fa79e32224480.png)]({{site.baseurl}}/assets/2021/08/0e00a89fcb68481aad7fa79e32224480.png)

#### jnz get_next_func

Jump near if not zero, caso a comparação anterior aponte como hash diferentes o código será direcionado para a função get_next_func, responsável por verificar a próxima função exportada do módulo atual. Caso os hashes sejam iguais continua para o fluxo da proxima instrução.

#### pop eax

Restaura para o registrador EAX o VMA da tabela de exports do módulo atual. Este valor foi salvo na pilha através do PUSH EAX realizado anteriormente.

[![]({{site.baseurl}}/assets/2021/08/11ba7a2da13e4e9abdccf6d1fc7f8a34.png)]({{site.baseurl}}/assets/2021/08/11ba7a2da13e4e9abdccf6d1fc7f8a34.png)

Colocamos um breakpoint nessa instrução, pois só chegaremos nela no momento em que os hashes forem iguais e posteriormente liberei a execução.

[![]({{site.baseurl}}/assets/2021/08/dadd5c5e07d046d2b792a7625c6bc5b0.png)]({{site.baseurl}}/assets/2021/08/dadd5c5e07d046d2b792a7625c6bc5b0.png)

[![]({{site.baseurl}}/assets/2021/08/fe1adf21706641a7bd213526c575cd32.png)]({{site.baseurl}}/assets/2021/08/fe1adf21706641a7bd213526c575cd32.png)

#### mov ebx, [eax+0x24]

Relembrando a estrutura da Export table

[![]({{site.baseurl}}/assets/2021/08/e65af62396474ecaa86ea23feaade247-1.png)]({{site.baseurl}}/assets/2021/08/e65af62396474ecaa86ea23feaade247-1.png)

Temos no offset 0x24 o array AddressOfNameOrdinals, sendo assim esta instrução copia o VMA do array AddressOfNameOrdinals para o registrador EBX

[![]({{site.baseurl}}/assets/2021/08/dade3a9912334bcfb6573adb18d485f0.png)]({{site.baseurl}}/assets/2021/08/dade3a9912334bcfb6573adb18d485f0.png)

[![]({{site.baseurl}}/assets/2021/08/7235f7e1e42345fbb5fbae23607b7d81.png)]({{site.baseurl}}/assets/2021/08/7235f7e1e42345fbb5fbae23607b7d81.png)

#### add ebx, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA da do array AddressOfNameOrdinals e o salva no registrador EBX

#### mov cx, [ebx + 2 * ecx]

Em ECX temos o índice da função desejada dentro da array AddressOfNames, como os arrays AddressOfNames e AddressOfNameOrdinals utilizam o mesmo índice podemos reaproveita-lo para endontrar o RVA da função dentro do array AddressOfNameOrdinals. Dentro da array AddressOfNames utiliamos ECX \* 4 para saltar em cada um dos registros da array, pois cada registro dentro da AddressOfNames é um valor DWORD, ja na array AddressOfNameOrdinals cada registro é um WORD, sendo assim iremos multiplicar por 0x02 para saltar em cada registro. Conforme podemos observar na tabela de exports do módulo kernel32.dll

[![]({{site.baseurl}}/assets/2021/08/7315b13c4f8948799c7b7da081ec7d7e.png)]({{site.baseurl}}/assets/2021/08/7315b13c4f8948799c7b7da081ec7d7e.png)

#### mov ebx, [eax + 0x1c]

Antes de utilizar o novo índice calculado anteriormente iremos pegar o RVA do AddressOfFunctions no índice 0x1c da Export table e o salva no registrador EBX

#### add ebx, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA da do array AddressOfFunctions e o salva no registrador EBX

#### mov eax, [ebx + 4 * ecx]

Resgata o RVA da função desejada dentro da array AddressOfFunctions utilizando o offset resgatado da array AddressOfNameOrdinals. Onde:

*   EDX: Endereço virtual do AddressOfFunctions
*   ECX: Índice da função desejada (resgatado do array AddressOfNameOrdinals)
*   ECX \* 4: Índice da função \* 4 bytes de cada endereço

#### add eax, edx

Adiciona o RVA com o BaseAddress do módulo atual para obter o VMA da função desejada e o salva no registrador EAX

Nota: Este ja é o endereço de execução da função e pode ser usado pela instrução **call eax** (por exemplo).

[![]({{site.baseurl}}/assets/2021/08/9f1a8e78225b4bb08c7b0502a31ddeaa.png)]({{site.baseurl}}/assets/2021/08/9f1a8e78225b4bb08c7b0502a31ddeaa.png)

### Funçao finish

```txt
finish:  
mov [esp+0x24], eax ; Overwrite the old EAX value with the desired api address for the upcoming popad  
pop ebx ; Clear off the current modules hash  
pop ebx ; Clear off the current position in the module list  
popad ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered  
pop ecx ; Pop off the origional return address our caller will have pushed  
pop edx ; Pop off the hash value our caller will have pushed  
push ecx ; Push back the correct return value  
jmp eax ; Jump into the required function  
```

#### mov [esp+0x24], eax

Altera o valor orginal do EAX adicionado na pilha pelo **pushad** para o endereço da função desejada (que recem calculamos). Este processo é necessário pois daqui algumas instruções iremos restaurar os registrados como estavm no momento da chamada da nossa função. Neste momento o WAX conterá o VMA da função que desejamos chamar.

#### pop ebx

Remove da pilha o hash do módulo atual

#### pop ebx

Remove da pilha a posição atual na listagem de módulos

#### popad

Restaura todos os registradores conforme seus valores iniciais. Nota para o EAX que será restaurado com o valor que sobrescrevemos a 2 instruçÕes.

#### pop ecx

Remove da pilha e copia para o registrador ECX o endereço de retorno do nosso fluxo de execução original. Este endereço foi adicionado automaticamente na pilha no momento da chamada da instrução CALL.

#### pop edx

Remove da pilha o hash da função que adicionamos antes da chamada da função call

#### push ecx

Adiciona novamente na pilha o endereço de retorno para que após a execução da função desejada o código possa continuar sua execução normalmente.

#### jmp eax

Salta para o endereço da função em que se deseja executar. Do ponto de vista do fluxo de código não continuaremos para as próximas instruções que será estudadas a segir, pois uma vez saltado para a função desejada a mesma finalizará com um RET que retornará, então, para nosso fluxo de execução original.

### Funções adicionais

```txt
get_next_mod: ;  
pop eax ; Pop off the current (now the previous) modules EAT  
get_next_mod1: ;  
pop edi ; Pop off the current (now the previous) modules hash  
pop edx ; Restore our position in the module list  
mov edx, [edx] ; Get the next module  
jmp next_mod ; Process this module  
```

Conforme podemos visualizar ha outras funções no final do código da biblioteca que ja foram referenciados anteriormente e fazem parte do processo de execução.

Conclusão
---------

Como vimos através do estudo da biblioteca block_api é possível localizar em tempo de execução todos os módulos carregados no sistema, inclusive os carregados em tempo de execução, e suas respectivas funções exportadas.

Treinamento
-----------

Deseja aprender passo a passo como realizar a criação de um Shellcode? Então da uma olhada em nosso treinamento de Shellcoding onde vamos do zero a criação de um shell reverso windows e linux, passando por shellcoding 32 e 64 bits.

Link do treinamento: [https://sec4us.com.br/treinamentos/shellcoding-para-desenvolvimento-de-exploits/](https://sec4us.com.br/treinamentos/shellcoding-para-desenvolvimento-de-exploits/)

[![]({{site.baseurl}}/assets/2021/08/image)](https://sec4us.com.br/treinamentos/shellcoding-para-desenvolvimento-de-exploits/)

Fontes
-------

*   Pavel, Y at all. Windows Internals Part 1: 7. ed. Washington: Microsoft, 2017.
*   Russinovich, M at all. Windows Internals: 5. ed. Washington: Microsoft, 2009.
*   [https://en.wikipedia.org/wiki/Win32_Thread_Information_Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
*   [https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
*   [https://www.aldeid.com/wiki/PE-Portable-executable](https://www.aldeid.com/wiki/PE-Portable-executable)
*   [https://docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
*   [https://infoslack.com/devops/linux-101-arquitetura](https://infoslack.com/devops/linux-101-arquitetura)
*   [https://en.wikipedia.org/wiki/Address_space_layout_randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
*   [https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
*   [https://www.youtube.com/watch?v=ySKEF8MHcZA](https://www.youtube.com/watch?v=ySKEF8MHcZA)
*   [https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm)
*   [https://cheatsheet.sec4us.com.br/shellcoding](https://cheatsheet.sec4us.com.br/shellcoding)

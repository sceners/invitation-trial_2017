; «Low-level programming is good for the programmer's soul.» - John Carmack
; ---- skeleton -----------------------------------------------------------
.686
.mmx			
.model flat, stdcall
option casemap :none

; ---- Include ------------------------------------------------------------
include		\masm32\include\windows.inc
include		\masm32\include\user32.inc
include		\masm32\include\kernel32.inc
include		\masm32\include\comctl32.inc
include		\masm32\include\gdi32.inc
include		\masm32\include\winmm.inc
include		\masm32\macros\macros.asm
include		Libs\ufmod.inc
include		Libs\XXControls.inc
include 	Libs\biglib.inc
include 	Libs\cryptohash.inc
include 	Libs\Aboutb0x.inc

includelib	\masm32\lib\gdi32.lib
includelib	\masm32\lib\winmm.lib
includelib	\masm32\lib\user32.lib
includelib	\masm32\lib\kernel32.lib
includelib	\masm32\lib\comctl32.lib
includelib	Libs\ufmod.lib
includelib	Libs\XXControls.lib
includelib 	Libs\biglib.lib
includelib 	Libs\cryptohash.lib

; ---- Prototypes ---------------------------------------------------------
DlgProc					PROTO :DWORD,:DWORD,:DWORD,:DWORD
DialogProc2 			PROTO :DWORD,:DWORD,:DWORD,:DWORD
CenterWindow			PROTO :DWORD
DrawXXControlButtons	PROTO :DWORD
DrawEffects				PROTO :HWND
KeygenProc 				PROTO
CleanBuffers			PROTO

; ---- constants ----------------------------------------------------------
.const
DIALOG_2		equ	2
IDC_MUSIC		equ 1008
IDD_MAIN    	equ	1337
IDC_TITLE		equ	1010
IDB_EXIT		equ	1011
IDB_EXIT2		equ	1012
IDC_NAME		equ	1013
IDC_SERIAL		equ	1014
BTN_CHECK		equ	1017
IDB_NOSOUND		equ	1018
EFFECTS_HEIGHT	equ	207
EFFECTS_WIDTH	equ	344
MAXSiZE			equ 256
bufSize = MAX_COMPUTERNAME_LENGTH + 1

; ---- Initialized data ---------------------------------------------------
.data
;PC name check
computer 		db "UEMtUEM=",0 ; PC-PC
buffer    		db 100 dup(?)
bSize 			dd bufSize
getName 		db bufSize dup(?)
nameb64 		db bufSize dup(?)

;move windows derfinition for the second dialog
MoveDlg				BOOL		?
OldPos				POINT		<>
NewPos				POINT		<>
Rect2				RECT		<>

;Algo stuff
E 				db "10001",0
N 				db "9F58207FFC1F211A3D3B4853CA98441DDF9C8D4C95EA7E3A9D4E80FD2E0A4F81",0
;D 				db "6F4A70E092E9F707C98E7734B6C26487CEB7BB7D55DC1EEC0C78F5AE945B22C5",0
;P				db "EF16D9B6532A35EA5BB6418EAFD4E9FB",0
;Q				db "AA9D58C6A8B610CC5A605E7C4A4F0FB3",0

name_input		dd 	MAXSiZE dup (00)
serial_input	dd 	MAXSiZE dup (00)
md5				dd 	MAXSiZE dup (00)
hex_name		dd 	MAXSiZE dup (00)
rsa				dd 	MAXSiZE dup (00)
UnRev			dd 	MAXSiZE dup (00)
serialfp1 		dd 	MAXSiZE dup (00)
serialfp2 		dd 	MAXSiZE dup (00)
serialfp3 		dd 	MAXSiZE dup (00)

szTitle						db "Temari.fr - Invitation #1",0

;Realease disclaimer (not used here)
;szMBoxTitle 				db "Message à caractère informatif",0
;szMBoxText					db "[GRP] will not be responsible for and do *NOT* support warez",13,10
;							db "distributions of this release. It is forbidden to include one of",13,10
;							db "our release in a warez distribution. Groups or individual will be",13,10
;							db "exposed for this !",0

pIntroBackBufferThreadID	dd 0
screenHeight				dd 0
screenWidth					dd 0
dwColor						dd 0
wDC1 						dd 0
wDC2 						dd 0
y 							dd 0
x 							dd 0
x1							dd 0
R							dd 0
G							dd 0
B							dd 0
B1							dd 0
B2							dd 0
B3							dd 0
B4							dd 0
B5							dd 0
B6							dd 0
status 						dd ?

; ---- Uninitialized data -------------------------------------------------
.data? 
iHWND		dd 			?
hInstance	dd			?
hBlackBrush	HBRUSH		?
hExit		BOOL		?
handle		dd			?
hMatrix		DWORD		?
hDC			HANDLE		?
ppv1		dd			?
srcdc1		dd			?
hdcx1		dd			?

bigM 		dd 			?
bigC 		dd 			?
bigN 		dd 			?
bigE 		dd 			?
name_len	dd 			?

; ---- Macro --------------------------------------------------------------
$invoke MACRO Fun:REQ, A:VARARG
  IFB <A>
    invoke Fun
  ELSE
    invoke Fun, A
  ENDIF
  EXITM <eax>
ENDM

; ---- Code ---------------------------------------------------------------
.code 
start: 
;	MASM32 	antiPeID fake ExeCryptor`s OEP
	db 0E8h,024h,000h,000h,000h,08Bh,04Ch,024h,00Ch,0C7h,001h,017h,000h,001h,000h,0C7h
	db 081h,0B8h,000h,000h,000h,000h,000h,000h,000h,031h,0C0h,089h,041h,014h,089h,041h
	db 018h,080h,0A1h,0C1h,000h,000h,000h,0FEh,0C3h,031h,0C0h,064h,0FFh,030h,064h,089h
	db 020h

	ASSUME FS:NOTHING
	POP FS:[0]
	ADD ESP,4
	
	call IsDebuggerPresent
    test     eax,eax
    popa 
    jz @F ;No debug
    push 0
    call ExitProcess
@@:
	; Inspired from a malware (Satan RaaS)
	invoke BlockInput,TRUE
	invoke BlockInput,FALSE
	
	; Check PC name
	invoke GetComputerName,ADDR getName,ADDR bSize
	invoke wsprintf,ADDR buffer,chr$("%s"),ADDR getName
	invoke lstrlen,addr buffer
	invoke Base64Encode,addr buffer,eax,addr nameb64
	invoke lstrcmp,addr nameb64,addr computer
	TEST EAX,EAX
	jnz @scnd
	
	invoke	InitCommonControls
	mov hBlackBrush,$invoke	(CreateSolidBrush,Black)
	mov	hInstance,$invoke	(GetModuleHandle, NULL)
	
	invoke	DialogBoxParam, hInstance, IDD_MAIN, NULL, offset DlgProc, 0
	invoke	ExitProcess,NULL
	
	; Display the second dialog if not the good name
	@scnd:
	    invoke  GetModuleHandle, NULL
    	mov hInstance, eax
		invoke DialogBoxParam,hInstance,DIALOG_2,NULL, offset DialogProc2, 0
		invoke ExitProcess,NULL

DialogProc2 Proc hWnd:dword, uMsg:dword, wParam:dword, lParam:dword
		PUSHAD
		mov EAX,hWnd
		mov hWnd,EAX
		.if uMsg==WM_INITDIALOG  
			invoke uFMOD_PlaySong,IDC_MUSIC,hInstance,XM_RESOURCE
			invoke	LoadIcon,hInstance,200
			invoke	SendMessage, hWnd, WM_SETICON, 1, eax
			invoke	SetWindowText,hWnd,chr$('temari.fr - Invitation #1')
		.elseif uMsg==WM_LBUTTONDOWN
		mov MoveDlg,TRUE
		invoke SetCapture,hWnd
		invoke GetCursorPos,addr OldPos	
		
		.elseif uMsg==WM_MOUSEMOVE
		.if MoveDlg==TRUE
		invoke GetWindowRect,hWnd,addr Rect2
		invoke GetCursorPos,addr NewPos
		mov eax,NewPos.x
		mov ecx,eax
		sub eax,OldPos.x
		mov OldPos.x,ecx
		add eax,Rect2.left
		mov ebx,NewPos.y
		mov ecx,ebx
		sub ebx,OldPos.y
		mov OldPos.y,ecx
		add ebx,Rect2.top
		mov ecx,Rect2.right
		sub ecx,Rect2.left
		mov edx,Rect2.bottom
		sub edx,Rect2.top
		invoke MoveWindow,hWnd,eax,ebx,ecx,edx,TRUE
		.endif
		.elseif uMsg==WM_LBUTTONUP
		mov MoveDlg,FALSE
		invoke ReleaseCapture
		.elseif uMsg==WM_LBUTTONDBLCLK
           invoke EndDialog,hWnd,0
		.elseif uMsg==WM_RBUTTONDBLCLK
           invoke EndDialog,hWnd,0
		.elseif uMsg==WM_COMMAND
		.elseif uMsg==WM_CLOSE
			@CLOSEiT:	
				invoke uFMOD_PlaySong,0,0,0
				invoke EndDialog,hWnd,NULL
				JMP @End
			.else
			POPAD
			MOV EAX,FALSE
			RET	
		.endif
		@End:		
			POPAD
			XOR EAX,EAX
			RET 
DialogProc2 endp	

DlgProc proc uses esi edi hWnd:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
local rect:RECT,hDrawEffects:HANDLE
		PUSHAD
		mov EAX,hWnd
		mov iHWND,EAX
		PUSHAD
		mov	eax,uMsg
		push hWnd
	;pop handle
	.if	uMsg == WM_INITDIALOG
		invoke GetParent,hWnd
		mov ecx,eax
		invoke GetWindowRect,ecx,addr rect
		mov edi,rect.left
		mov esi, rect.top
		add edi,25
		add esi,100

		;invoke MessageBox,NULL,ADDR szMBoxText,ADDR szMBoxTitle,MB_ICONINFORMATION
		
		invoke  CreateTVBox,iHWND
		invoke	LoadIcon,hInstance,200
		invoke	SendMessage, hWnd, WM_SETICON, 1, eax
		invoke  uFMOD_PlaySong,400,hInstance,XM_RESOURCE
		invoke	SetDlgItemText,hWnd,IDC_TITLE,addr szTitle
		invoke	SetWindowText,iHWND,chr$('temari.fr - Invitation #1')
		invoke	SetDlgItemText,iHWND,IDC_NAME,chr$('iNViTATiON')
		invoke	CenterWindow,hWnd
		invoke	DrawXXControlButtons,hWnd
		
		mov hMatrix,$invoke	(VirtualAlloc,NULL,0*EFFECTS_WIDTH+100,MEM_COMMIT,PAGE_READWRITE)
		invoke	BuildMatrix
		mov hDrawEffects,$invoke (CreateThread,NULL,0,addr DrawEffects,hWnd,0,addr pIntroBackBufferThreadID)
		invoke	SetThreadPriority,hDrawEffects,THREAD_PRIORITY_NORMAL
		mov status,1 ; Declare the sound control button statut
		.elseif uMsg==WM_COMMAND
			MOV EAX,wParam
			.IF ax==BTN_CHECK
				invoke GetDlgItemText,iHWND,IDC_NAME,ADDR name_input,MAXSiZE
				.if eax == 0
					invoke MessageBox,iHWND,chr$("NAME STATUS: NO NAME"),chr$("Status"),MB_ICONEXCLAMATION
				.elseif eax > 15
					invoke MessageBox,iHWND,chr$("NAME STATUS: TOO LONG"),chr$("Status"),MB_ICONEXCLAMATION
				.elseif eax < 3
					invoke MessageBox,iHWND,chr$("NAME STATUS: TOO SHORT"),chr$("Status"),MB_ICONEXCLAMATION
				.elseif
					invoke GetDlgItemText,iHWND,IDC_SERIAL,ADDR serial_input,MAXSiZE
					.if eax == 0
						invoke MessageBox,iHWND,chr$("SERiAL STATUS: NO SERiAL"),chr$("Status"),MB_ICONEXCLAMATION
					.elseif eax > 108
						invoke MessageBox,iHWND,chr$("SERiAL STATUS: TOO LONG"),chr$("Status"),MB_ICONEXCLAMATION
					.elseif eax < 107
						invoke MessageBox,iHWND,chr$("SERiAL STATUS: TOO SHORT"),chr$("Status"),MB_ICONEXCLAMATION
					.elseif
						invoke KeygenProc
					.endif
				.endif
			.endif
		.if	ax == IDB_EXIT || eax == IDB_EXIT2
		mov hExit,TRUE
			invoke	SendMessage, hWnd, WM_CLOSE, 0, 0
			.endif	
		.if ax==IDB_NOSOUND
			.if status == 1
				invoke SetDlgItemText,iHWND,IDB_NOSOUND,chr$(">")
				invoke uFMOD_PlaySong,0,0,0
				mov status,0
			.else
				invoke SetDlgItemText,iHWND,IDB_NOSOUND,chr$("<")
				invoke  uFMOD_PlaySong,400,hInstance,XM_RESOURCE
				mov status,1
			.endif
		.endif
.elseIF uMsg == WM_CTLCOLORDLG
		mov eax,wParam
		invoke SetBkColor,eax,Black
		invoke GetStockObject,BLACK_BRUSH
		ret
.elseif uMsg==WM_CTLCOLOREDIT || uMsg==WM_CTLCOLORSTATIC
		invoke SetBkMode,wParam,OPAQUE
		invoke SetBkColor,wParam,000000h
		invoke SetTextColor,wParam,0FCDC7Ch
		invoke GetStockObject,BLACK_BRUSH
		ret
.elseif uMsg == WM_CTLCOLORBTN
      invoke CreateSolidBrush, 000000FFh
      ret
      
	.elseif eax==WM_LBUTTONDOWN
		invoke SendMessage,hWnd,WM_NCLBUTTONDOWN,HTCAPTION,0
	.elseif eax==WM_RBUTTONDOWN
		invoke SendMessage,hWnd,WM_CLOSE,0,0
	.elseif	eax == WM_CLOSE
	invoke AnimateWindow,hWnd,500,AW_HIDE or AW_BLEND
		invoke uFMOD_PlaySong,0,0,XM_RESOURCE
		invoke TerminateThread,threadID,0
		invoke DeleteDC,srcdc
		invoke	EndDialog, hWnd, 0
	.endif
				
	xor	eax,eax
	ret
DlgProc endp

KeygenProc PROC

; ---- KEYGEN PROC --------------------------------------------------------
; iNViTATiON
; iNViTATiON-75596E86CE496F7A6DAFE2EFB3C6D2AE7FC06574663E0AFC2E895C2ED1E15C37-D2885F77ADF18405B04CB07979611DB3

	cmp byte ptr ss:[serial_input+10],02Dh
	jnz @wrong
	cmp byte ptr ss:[serial_input+75],02Dh
	jnz @wrong

	invoke lstrcpyn,addr serialfp1,addr serial_input,10 + 1
	invoke lstrcpyn,addr serialfp2,addr serial_input + 11,64 + 1
	invoke lstrcpyn,addr serialfp3,addr serial_input + 76,32 + 1

	invoke lstrcmp,addr serialfp1,chr$("iNViTATiON")
	TEST EAX,EAX
	jnz @wrong

	invoke lstrlen,addr name_input
	mov name_len,eax

	invoke HexEncode,addr name_input,name_len,addr hex_name
	lea esi,serialfp2
	call REVERSEiT

	invoke _BigCreate,0
	mov bigM,eax
	invoke _BigCreate,0
	mov bigN,eax
	invoke _BigCreate,0
	mov bigE,eax
	invoke _BigCreate,0
	mov bigC,eax
	invoke _BigIn,addr UnRev,16,bigM
	invoke _BigIn,addr E,16,bigE
	invoke _BigIn,addr N,16,bigN
	invoke _BigPowMod,bigM,bigE,bigN,bigC
	invoke _BigOutB16,bigC,addr rsa
	invoke _BigDestroy,bigM
	invoke _BigDestroy,bigE
	invoke _BigDestroy,bigN
	invoke _BigDestroy,bigC

	invoke lstrcmp,addr hex_name,addr rsa
	TEST EAX,EAX
	jnz @wrong

	invoke MD5Init
	invoke MD5Update,addr name_input,name_len
	invoke MD5Final
	invoke HexEncode,eax,MD5_DIGESTSIZE,addr md5
	invoke lstrcmp,addr serialfp3,addr md5
	TEST EAX,EAX
	jnz @wrong

	invoke MessageBox,iHWND,chr$("SERiAL STATUS: REGiSTERED"),chr$("Status"),MB_ICONINFORMATION
	CALL CLEAR
	RET

	@wrong:
	invoke MessageBox,iHWND,chr$("SERiAL STATUS: UNREGiSTERED"),chr$("Status"),MB_ICONERROR
	CALL CLEAR
	RET

KeygenProc ENDP

CLEAR proc
	invoke RtlZeroMemory,addr name_input,MAXSiZE
	invoke RtlZeroMemory,addr serial_input,MAXSiZE
	invoke RtlZeroMemory,addr md5,MAXSiZE
	invoke RtlZeroMemory,addr rsa,MAXSiZE
	invoke RtlZeroMemory,addr UnRev,MAXSiZE	
	RET
CLEAR endp

REVERSEiT PROC
	lea edi, UnRev
	mov ecx, 40h
	xor ebx, ebx
	Reversor:
		mov al, byte ptr[esi+ecx-1]
		mov byte ptr[edi+ebx], al
		inc ebx
		dec ecx
	jnz Reversor
		mov byte ptr[edi+ebx], 0
	Ret
REVERSEiT ENDP

DrawEffects	Proc hWnd:HWND
	local bmpi1:BITMAPINFO
; ---- Activate Vectors ---------------------------------------------------

			mov hDC,$invoke (GetDC,hWnd)
			invoke CreateCompatibleDC,hDC
			mov wDC1,eax
			mov wDC2,eax
			invoke CreateCompatibleBitmap,hDC,EFFECTS_WIDTH,1
			invoke SelectObject,wDC1,eax
			invoke DeleteObject,eax
			invoke CreateCompatibleBitmap,hDC,EFFECTS_WIDTH,1
			invoke SelectObject,wDC2,eax
			invoke DeleteObject,eax
			_back:
			invoke DrawColorScroller
			.if hExit != TRUE
				invoke	Sleep,20
				invoke BitBlt,hDC,left,29,EFFECTS_WIDTH,1,wDC1,0,0,SRCCOPY
				invoke BitBlt,hDC,left,25+EFFECTS_HEIGHT,EFFECTS_WIDTH,1,wDC2,0,0,SRCCOPY
				
				invoke BitBlt,hDC,344,29,EFFECTS_WIDTH,1,wDC1,0,0,SRCCOPY
				invoke BitBlt,hDC,344,25+EFFECTS_HEIGHT,EFFECTS_WIDTH,1,wDC2,0,0,SRCCOPY

				jmp _back
			.endif	
			mov x1,0
		invoke	DeleteDC,wDC1
		invoke	DeleteDC,wDC2
	Ret
DrawEffects endp

DrawColorScroller	Proc
	mov esi,hMatrix
	mov x,0
	; Commented commands would be useful only when we build a matrix on screen, instead of 2 scrolling vectors
	;mov y,0
	;	.repeat
			.repeat
				mov eax,x1
				add eax,x
				mov ebx,EFFECTS_WIDTH
				xor edx,edx
				idiv ebx
				push edx
				invoke SetPixel,wDC1,edx,y,dword ptr [esi]
				mov eax,EFFECTS_HEIGHT
			;	add eax,y
				pop edx
			;	add esi,EFFECTS_WIDTH*4*EFFECTS_HEIGHT-EFFECTS_WIDTH*4
			;	sub esi,20h
				invoke SetPixel,wDC2,edx,eax,dword ptr [esi]
			;	add esi,20h
			;	sub esi,EFFECTS_WIDTH*4*EFFECTS_HEIGHT-EFFECTS_WIDTH*4
				add esi,4
				inc x
			.until x == EFFECTS_WIDTH
			mov x,0
	;		inc y
	;	.until y == 1 ;EFFECTS_HEIGHT
	;	mov y,0
		add x1,5		;	Speed of wave
	Ret
DrawColorScroller endp


CenterWindow	Proc hWnd:HWND
LOCAL rc:RECT
	mov screenWidth,$invoke	(GetSystemMetrics,SM_CXSCREEN)
	mov screenHeight,$invoke (GetSystemMetrics,SM_CYSCREEN)
	invoke	GetWindowRect,hWnd,addr rc
	mov eax,rc.right
	sub eax,rc.left
	mov ecx,screenWidth
	sub ecx,eax
	shr ecx,1
	mov eax,rc.bottom
	sub eax,rc.top
	mov edx,screenHeight
	sub edx,eax
	shr edx,1
	invoke	SetWindowPos,hWnd,0,ecx,edx,0,0,5;SWP_NOZORDER || SWP_NOSIZE
	Ret
CenterWindow endp

DrawXXControlButtons	Proc	hWnd:HWND
LOCAL sButtonStructure:XXBUTTON,hSmallButtonFont:HFONT,hBtn:HWND
	mov hSmallButtonFont,$invoke	(CreateFont,8,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_CHARACTER_PRECIS,CLIP_CHARACTER_PRECIS,PROOF_QUALITY,FF_DONTCARE,chr$('MS Sans Serif'))
	invoke	RtlZeroMemory,addr sButtonStructure,sizeof sButtonStructure
	invoke	LoadCursor,NULL,IDC_HAND
	mov sButtonStructure.hCursor_hover,eax
	mov sButtonStructure.hover_clr,White
	mov sButtonStructure.push_clr,White
	mov sButtonStructure.normal_clr,White
	mov sButtonStructure.btn_prop, 08000000Fh
	mov hBtn,$invoke	( GetDlgItem,hWnd,IDB_EXIT2 )
	invoke	RedrawButton,hBtn,addr sButtonStructure
	mov sButtonStructure.push_clr,0B0B0B0h
	mov sButtonStructure.btn_prop,08000000Bh
	mov hBtn,$invoke	( GetDlgItem,hWnd,IDB_EXIT )
	invoke	RedrawButton,hBtn,addr sButtonStructure
	mov hBtn,$invoke	( GetDlgItem,hWnd,BTN_CHECK )
	invoke	RedrawButton,hBtn,addr sButtonStructure
	mov hBtn,$invoke	( GetDlgItem,hWnd,IDB_NOSOUND )
	invoke	RedrawButton,hBtn,addr sButtonStructure
	
	invoke	SetFocus,eax
	mov eax,TRUE
	Ret
DrawXXControlButtons endp

end start
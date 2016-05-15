; ###############################################################################;
; DESCRIPTION: This code provide a simple (and not optimized) example 
;            : of PE analisys. Find DOS Header, NT Header, show sections, and you 
;            : can add a new section.
;            ; ------------------------------------------------------------------;
; UPDATE     : - Now PE Analyzer show to you the Import Table!
;            : - Menu Added;
;            ; ------------------------------------------------------------------;
;            : Future version: add more functionality.
;            : 
;            : NOTE: 
;            : Please, backup the original exe before adding a new section!
;            : (seems to be stable!)
; -------------------------------------------------------------------------------;
; COMPILATION: ml /c /coff file.asm
; LINKING    : link /SUBSYSTEM:CONSOLE file
; -------------------------------------------------------------------------------;
; AUTHOR     : Marco 'RootkitNeo' C.
; -------------------------------------------------------------------------------;
; LANGUAGE   : MASM32 (CUI Application)
; -------------------------------------------------------------------------------;
; VERSION    : 0.9.9 (Beta) 
; -------------------------------------------------------------------------------;
; LICENSE    : GNU/GPL V.3
; ###############################################################################;



include     c:\masm32\include\masm32rt.inc


; Data Section
; -------------------------------------------------------------------------------
.data
dosHeader              IMAGE_DOS_HEADER < >
ntHeader               IMAGE_NT_HEADERS < >

BUFFER_MAX             =    4

crlf                   db   13,10,0
crlf2                  db   13,10,13,10,0
tab                    db   9,0

FileName               db   MAX_PATH   dup(?)

welcome                db   "Welcome in PE Analyzer V. 0.9.9",13,10,"Software developed by Marco 'RootkitNeo' C.",13,10,13,10,0
                            
menu                   db   13,10,13,10,"Select an option:",13,10,"1. Read Section Table",13,10,
                            "2. Add Section",13,10,"3. Show Import Table",13,10,"4. Exit",13,10,0
; add section strings
newSectionString       db   13,10,13,10,"Section Name: ",0
sectionSizeString      db   13,10,"Size: ",0

; read file and check if is valid
fnameString            db   "Enter File Name: ",0
openfileString         db   "Opening File...",13,10,0
readSuccessString      db   13,10,"File Successiful read!",13,10,0
fileOffsetString       db   9,"File offset: 0x",0
validHeaderString      db   13,10,13,10,"Valid PE Header ",13,10,0
validNtHeaderString    db   13,10,13,10,"Valid NT Signature ",13,10,13,10,0
writeSuccessString     db   13,10,13,10,"File successiful saved",13,10,0

; Sections
sectionNameString      db   13,10,13,10,"Name: ",0
virtualSizeString      db   13,10,"Virtual Size: 0x",0
virtualAddrString      db   13,10,"Virtual Address: 0x",0
sizeRawDataString      db   13,10,"Size Of Raw Data: 0x",0
ptrRawDataString       db   13,10,"Pointer To Raw Data: 0x",0
charactString          db   13,10,"Characteristics: 0x",0
addNewSectionString    db   13,10,13,10,"Add New Section? ('y', 'n'): ",0

; Import table
importTableString      db   13,10,"Import Table:",13,10,0
nameModuleString       db   "Module Name: ",0
functionsNameString    db   "Functions: ",13,10,0

; Error messages
createError            db   "Cannot open the file.",13,10,0
allocError             db   "Cannot allocate the memory.",13,10,0
readError              db   "Cannon read the file.",13,10,0
invalidDosHeader       db   "Invalid DOS Header.",13,10,0
invalidNtHeader        db   "Invalid NT Header.",13,10,0
writeErrorString       db   "Write Error",0
importTableErrorString db   "IT doesn't exist",13,10,0
ordinalString          db   "Imported by Ordinal: 0x",0

closeFailed            db   "Close failed",13,10,0

showMoreText           db   13,10,"...[Press 'ESC' for go back to menu]...",0
;---------------------------------------------------------------------------------


; BSS Section
;---------------------------------------------------------------------------------
.data?
BaseAddress            dd            ?
hFile                  DWORD         ?
FileSize               DWORD         ?
BR                     DWORD         ?
buffer1                db   9    dup(?)
buffer2                db   40   dup(?)
buffer                 db   4    dup(?)
choice                 db   4    dup(?)
sectionName            db   20   dup(?)
sectionSizeS           db   100  dup(?)
importName             db            ?

sectionSize            dw            ?
nameSize               dd            ?
numberOfSections       dw            ?
;---------------------------------------------------------------------------------



; Code section
;---------------------------------------------------------------------------------
.code
start:
  call    main
  
  invoke  GetProcessHeap
  invoke  HeapFree, eax, 0, BaseAddress
  invoke  CloseHandle, hFile
  
  cmp     eax, 0 ; CloseHandle fail?
  jne     _exit
  
  push    offset closeFailed
  call    StdOut
  
_exit:
  inkey

  push    0
  call    ExitProcess
  
  
; // Main function
; --------------------------------------------------------------------- 
main      proc
  push    offset welcome
  call    StdOut
  
  call    loadFile
  cmp     eax,0         ; 0 = load failed --> exit program
  jne     skip_menu
  
  call    readDosHeader
  cmp     eax, 0        ; 0 = DOS header doesn't exist --> exit program
  jne     skip_menu
  
  call    readNtHeader
  cmp     eax, 0        ; 0 = NT Header doesn't exist --> exit program
  jne     skip_menu
  
menu_label:
  print   offset menu

  push    4
  push    offset choice
  call    StdIn
  
  cmp     [choice], 31h      ; 1
  jne     else_if1
  call    readSectionTable
  jmp     menu_label
else_if1:
  cmp     [choice], 32h      ; 2
  jne     else1
  call    addNewSection
  jmp     menu_label
else1:
  cmp     [choice], 33h      ; 3
  jne     exit_menu
  call    readImportDescriptor
  jmp     menu_label
exit_menu:
  cmp     [choice], 34h      ; 4
  je      skip_menu
  jmp     menu_label
  
skip_menu:
    
  ret
main      endp
; ---------------------------------------------------------------------
; // End Main


; Read Dos Header
; ---------------------------------------------------------------------  
loadFile  proc

  print    offset fnameString
  
  ; Read file name
  push    MAX_PATH
  push    offset FileName
  call    StdIn
  
  print   offset openfileString
   
  ; Create file (Open file and get HANDLE)
  invoke  CreateFile, addr FileName, GENERIC_READ or GENERIC_WRITE ,FILE_SHARE_READ OR FILE_SHARE_WRITE,0, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
  mov     hFile, eax
  
  cmp     hFile,INVALID_HANDLE_VALUE
  jne     createSuccess
  print   offset createError

  mov     eax, 1
  ret
  
createSuccess:
  invoke  GetFileSize,hFile,0
  mov     FileSize,eax
  
  invoke  GetProcessHeap
  invoke  HeapAlloc, eax, HEAP_NO_SERIALIZE + HEAP_ZERO_MEMORY, FileSize
  mov     BaseAddress, eax
  
  cmp     BaseAddress, NULL
  jne     allocSuccess
  print   offset allocError

  mov     eax, 1
  ret
  
  ; Memory allocation successiful. Now we can read...
allocSuccess:
  invoke  ReadFile, hFile, BaseAddress, FileSize, addr BR,0
  
  cmp     eax, 0
  jne     readSuccess
  print   offset readError
  
  mov     eax, 1
  
readSuccess:
  print   offset readSuccessString
  
  mov     eax, 0
  
  ret

loadFile      endp
; ---------------------------------------------------------------------  
; // End load file
 
;
; DOS Header
; ---------------------------------------------------------------------
readDosHeader  proc  
  ; same as C:
  ; BYTE             *BaseAddress;
  ; IMAGE_DOS_HEADER *dosHeader;
  ; ..... (allocation memory for BaseAddress) ....
  ; dosHeader = (IMAGE_DOS_HEADER *) BaseAddress;
  invoke  RtlMoveMemory, ADDR dosHeader, BaseAddress, SIZEOF dosHeader
  
  cmp     dosHeader.e_magic, IMAGE_DOS_SIGNATURE ; MZ ?
  je      valid_dos_header
  print   offset invalidDosHeader

  mov     eax, 1
  ret

valid_dos_header:
  print   offset validHeaderString
  
  print   offset fileOffsetString
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  invoke  dw2hex,dosHeader.e_lfanew,addr buffer
  print   offset buffer
  
  mov     eax, 0
  
  ret      

readDosHeader   endp
; ---------------------------------------------------------------------
;

;
; NT Header
; --------------------------------------------------------------------- 
readNtHeader    proc
  mov     eax, BaseAddress
  add     eax, [dosHeader.e_lfanew]
  invoke  RtlMoveMemory, ADDR ntHeader, eax, SIZEOF ntHeader
  
  cmp     ntHeader.Signature, IMAGE_NT_SIGNATURE   ; PE ?
  je      valid_nt_header
  print   offset invalidNtHeader

  mov     eax, 1
  ret

valid_nt_header:
  print   offset validNtHeaderString
  
  mov     eax, 0
  
  ret

readNtHeader    endp
; ---------------------------------------------------------------------
; End NT Header

;
; Image Section Header
; ---------------------------------------------------------------------
readSectionTable   proc uses esi
  
  xor     ebx, ebx
  xor     esi, esi
  
  call    findNTHeader
  assume  esi:ptr IMAGE_FILE_HEADER
  
  xor     ecx, ecx
  mov     cx, [esi].NumberOfSections
  movzx   ecx, cx
  
  call    findSectionHeader ; ...and store it's address in ESI register
  assume  esi:ptr IMAGE_SECTION_HEADER
  
  
  ; Print sections
show_sections:
  cmp     ecx, 0
  je      exit_show
  
  ; Push ecx because lstrcpyn don't use
  ; register preservation...
  push    ecx
 
  push    offset sectionNameString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer1,9
  invoke  lstrcpyn,addr buffer1,addr [esi].Name1,8
  print   offset buffer1
  
  push    offset virtualSizeString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  invoke  dw2hex, [esi].Misc.VirtualSize, addr buffer
  print   offset  buffer
  
  push    offset virtualAddrString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  invoke  dw2hex, [esi].VirtualAddress, addr buffer
  print   offset buffer
  
  push    offset sizeRawDataString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  invoke  dw2hex, [esi].SizeOfRawData, addr buffer
  print   offset buffer
  
  push    offset ptrRawDataString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  invoke  dw2hex, [esi].PointerToRawData, addr buffer
  print   offset buffer
  
  push    offset charactString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  invoke  dw2hex, [esi].Characteristics, addr buffer
  print   offset buffer
  
  pop     ecx ; get the previously pushed value
  
  dec     ecx
  add     esi, 28h
  
  jmp     show_sections

exit_show:
  
  ret
readSectionTable  endp
; ---------------------------------------------------------------------
; End Image Section Header

;
; Add new section
; ---------------------------------------------------------------------
addNewSection    proc uses esi edi
  
  push    offset newSectionString
  call    StdOut
  
  push    20
  push    offset sectionName
  call    StdIn
  
  push    offset sectionSizeString
  call    StdOut
  
  push    100
  push    offset sectionSizeS
  call    StdIn
  
  invoke  atodw, offset sectionSizeS    ; string number to number
  mov     sectionSize, ax
  xor     eax, eax
  
  call    findNTHeader
  assume  esi:ptr IMAGE_FILE_HEADER
  
  mov     ax, [esi].NumberOfSections
  mov     numberOfSections, ax
  inc     ax

  mov     [esi].NumberOfSections, ax
  
  add     esi, 14h ; OptionalHeader
  assume  esi:ptr IMAGE_OPTIONAL_HEADER
  
  mov     eax, [esi].SectionAlignment
  mov     dx, sectionSize
  movzx   edx, dx
  call    Alignment
  
  add     [esi].SizeOfImage, ecx
  
  xor     esi, esi
  call    findSectionHeader
  assume  esi:ptr IMAGE_SECTION_HEADER
  ; esi point to the address of the image section header
  mov     edi, esi
  call    findLastSection
  
  assume  edi:ptr IMAGE_SECTION_HEADER
  invoke  RtlZeroMemory, edi,IMAGE_SIZEOF_SECTION_HEADER
  
  invoke  szLen, addr sectionName
  cmp     eax, IMAGE_SIZEOF_SHORT_NAME
  jg      default_value
  mov     nameSize, eax
  jmp     jmp_else
default_value:
  mov     nameSize, IMAGE_SIZEOF_SHORT_NAME
jmp_else:
  invoke  RtlMoveMemory, addr [edi].Name1, addr sectionName ,nameSize
  
  xor     esi,esi
  call    findNTHeader
  add     esi, 14h ; OptionalHeader
  assume  esi:ptr IMAGE_OPTIONAL_HEADER
  
  mov     eax, [esi].SectionAlignment
  sub     edi, sizeof IMAGE_SECTION_HEADER
  mov     edx, [edi].VirtualAddress
  add     edx, [edi].Misc.VirtualSize
  call    Alignment
  
  add     edi, sizeof IMAGE_SECTION_HEADER
  mov     [edi].VirtualAddress, ecx
  mov     ax, sectionSize
  movzx   eax, ax
  mov     [edi].Misc.VirtualSize, eax
  
  sub     edi, sizeof IMAGE_SECTION_HEADER
  
  xor     edx, edx
  mov     eax, [edi].SizeOfRawData
  mov     ebx, [esi].FileAlignment
  div     ebx 
  cmp     edx, 0
  je      continue
  ; FASTCALL convention
  mov     eax, [esi].FileAlignment
  mov     edx, [edi].SizeOfRawData
  call    Alignment
  mov     [edi].SizeOfRawData, ecx
  mov     ebx, [edi].PointerToRawData
  add     ebx, [edi].SizeOfRawData
  invoke  SetFilePointer, hFile, ebx, NULL, FILE_BEGIN
  
  invoke  SetEndOfFile, hFile
continue:

  add     edi, sizeof IMAGE_SECTION_HEADER
  invoke  GetFileSize, hFile, NULL
  mov     FileSize, eax
  mov     [edi].PointerToRawData, eax
  
  mov     eax, [esi].FileAlignment
  mov     dx, sectionSize
  movzx   edx, dx
  call    Alignment
  
  mov     [edi].SizeOfRawData, ecx
  mov     [edi].Characteristics, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE
  mov     [edi].NumberOfRelocations, 0000h
  mov     [edi].NumberOfLinenumbers, 0000h
  mov     [edi].PointerToRelocations, 00000000h
  mov     [edi].PointerToLinenumbers, 00000000h
  
  
  invoke  SetFilePointer, hFile, [edi].SizeOfRawData, NULL, FILE_END
  invoke  SetEndOfFile, hFile
  
  invoke  SetFilePointer, hFile, 0, NULL, FILE_BEGIN
  invoke  WriteFile, hFile, BaseAddress,FileSize, addr BR, NULL
  
  cmp     eax, 0
  jne     write_success

  push    offset writeErrorString
  call    StdOut
  
  mov     eax, 1
  ret
write_success:
  push    offset writeSuccessString
  call    StdOut

  mov     eax, 0
  ret
  
addNewSection    endp
; ---------------------------------------------------------------------
;

; Print Import Table information
; ---------------------------------------------------------------------
readImportDescriptor  proc uses esi edi

  LOCAL   nameLen:DWORD

  call    findNTHeader
  add     esi, 14h
  assume  esi:ptr IMAGE_OPTIONAL_HEADER
  ; Get Import Table address into DataDirectory array
  ; sizeof IMAGE_DATA_DIRECTORY = 2nd member of the array -> Import Table (VirtualAddress) 
  mov     edx,[esi].DataDirectory[sizeof IMAGE_DATA_DIRECTORY].VirtualAddress

  ; EDX = RVA of the IT
  call    RVAToOffset
  cmp     edx, 0
  jne     continue_read_import ; if valid, read import
  
  push    offset importTableErrorString
  call    StdOut
  mov     eax, 0
  ret
  
  ; Read IMAGE_IMPORT_DESCRIPTOR
  ; each member is a DLL import
continue_read_import:
  mov     esi, edx
  add     esi, BaseAddress
  assume  esi:ptr IMAGE_IMPORT_DESCRIPTOR

  push    offset importTableString
  call    StdOut
  
while_descriptors:
  ; IMAGE_THUNK_DATA (basicly the RVA) 
  ; contains pointer to
  ; an IMAGE_IMPORT_BY_NAME
  cmp     [esi].FirstThunk, 0
  je      exit_descriptors_while
  
  ; Name of the module
  mov     edx, [esi].Name1
  
  push    esi
  
  call    findNTHeader
  add     esi, 14h
  assume  esi:ptr IMAGE_OPTIONAL_HEADER
  
  call    RVAToOffset
  add     edx, BaseAddress
  
  ; register preservation
  ; RtlZeroMemory change the value of EDX
  push    edx
  
  invoke  RtlZeroMemory,addr buffer,20
  push    offset nameModuleString
  call    StdOut
  
  pop     edx
  ; restore the previously pushed value
  
  invoke  lstrcpyn,addr buffer, edx,19
  print   offset buffer
  
  push    offset crlf
  call    StdOut
  
  push    offset functionsNameString
  call    StdOut
  
  pop     esi
  assume  esi:ptr IMAGE_IMPORT_DESCRIPTOR
  ; select correct array
  mov     edx, [esi].OriginalFirstThunk
  cmp     [esi].OriginalFirstThunk,0
  cmove   edx, [esi].FirstThunk
  push    esi
  
  ; same as before; convert RVA into file offset
  call    RVAToOffset
  add     edx, BaseAddress
  mov     edi, edx
  assume  edi:ptr IMAGE_IMPORT_DESCRIPTOR

  ; IMAGE_IMPORT_BY_NAME -> name of the functions
  ; imported by modules  
functions:
  push    offset tab
  call    StdOut

  cmp     dword ptr[edi], 0
  jz      exit_functions
  
  ; check if it is imported by name or ordinal
  test    dword ptr [edi],IMAGE_ORDINAL_FLAG32 
  jnz     importByOrdinal
  
  ; ---- Imported by name block ----
  mov     edx, dword ptr [edi]
  push    edi
  call    RVAToOffset
  pop     edi
  add     edx, BaseAddress
  assume  edx:ptr IMAGE_IMPORT_BY_NAME
  
  push    edx
  invoke  RtlZeroMemory,addr buffer2,40
  pop     edx

  invoke  lstrcpyn,addr buffer2,addr [edx].Name1,39
  
  push    offset buffer2
  call    StdOut
  jmp     printText
  ; --- imported by ordinal block -----
importByOrdinal:
  mov     edx, dword ptr [edi]
  and     edx, 0FFFFh
  
  push    edx
  push    offset ordinalString
  call    StdOut
  invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
  pop     edx
  invoke  dw2hex, addr [edx], addr buffer
  print   offset buffer
  
printText:

  push    offset crlf
  call    StdOut
  
  add     edi, 4
  jmp     functions  ; read the next function
  
exit_functions:
  push    offset showMoreText
  call    StdOut
  
  ;inkey   "...[Show More]..."
  getkey
  
  cmp     eax, 1Bh
  je      exit_descriptors_while
  
  push    offset crlf2
  call    StdOut
  
  pop     esi
  add     esi, sizeof IMAGE_IMPORT_DESCRIPTOR ; 'jmp' to the next entry
  
  jmp     while_descriptors  ; read the next module name
  
exit_descriptors_while:
  
  ret
readImportDescriptor  endp
; ------------------------------------------------------------------------
;





; #########################################
; #          UTILITY PROCEDURES           #
; #########################################


; Find first IMAGE_SECTION_HEADER
; ------------------------------------------------------
findSectionHeader proc

  mov     esi, BaseAddress
  add     esi, dosHeader.e_lfanew
  mov     bx, ntHeader.FileHeader.SizeOfOptionalHeader
  movzx   ebx, bx
  add     esi,ebx
  add     esi, 18h ; ESI -> block of sections
                   ; 18h -> Signature NT Header
  ret
findSectionHeader  endp
; -------------------------------------------------------
;

;
; --------------------------------------------------;
; Get Last Section (IMAGE_SECTION_HEADER)
; last section = the section inserted by user
; --------------------------------------------------;
findLastSection   proc

  xor     ecx, ecx
  
  find_section:
  cmp     cx, numberOfSections
  je      exit_find
  
  add     edi, sizeof IMAGE_SECTION_HEADER
  inc     cx
  jmp     find_section
  
exit_find:

  ret
  
findLastSection   endp
;---------------------------------------------------;
;

;
; --------------------------------------------------;
; Memory location of NT Header                      ;
; --------------------------------------------------;
findNTHeader proc

  xor     esi, esi
  
  mov     esi, BaseAddress
  add     esi, dosHeader.e_lfanew
  add     esi, 4h ; 4h = size of Signature
                  ; now ESI point to IMAGE_FILE_HEADER struct
  
  ret
findNTHeader endp
; --------------------------------------------------;
;

;
; --------------------------------------------------;
; FASTCALL:                                         ;
; EAX = first parameter                             ;
; EDX = second parameter                            ;
; --------------------------------------------------;
Alignment   proc
  
  mov     ecx, eax
  
calc:
  cmp     edx, ecx
  jle     exit_calc
  
  add     ecx, eax
  
  jmp     calc
exit_calc:
  
  ret
Alignment   endp
; ---------------------------------------------------;
;

;
; ---------------------------------------------------;
; Convert RVA address into File Offset               ;
; return value in EDX                                ;
; ---------------------------------------------------;
RVAToOffset   proc uses eax edi esi
  LOCAL   limit:DWORD
  
  call    findSectionHeader
  mov     edi, esi
  pop     esi
  assume  edi:ptr IMAGE_SECTION_HEADER
  ;EDI = first section
  
  cmp     edx, [edi].PointerToRawData
  jge     continue
  
  ret


continue:  
  push    ecx
  push    ebx
  
  xor     ecx, ecx
  mov     cx, ntHeader.FileHeader.NumberOfSections
  movzx   ecx, cx
while_sections:
  cmp     ecx, 0
  je      exit_while

  cmp     [edi].SizeOfRawData, 0
  jne     raw_data_0
  mov     eax, [edi].Misc.VirtualSize
  jmp     continue_else
raw_data_0:
  mov     eax, [edi].SizeOfRawData
  
continue_else:
  cmp     edx, [edi].VirtualAddress
  jge     control_and
  jmp     continue_while
control_and:
  add     eax, [edi].VirtualAddress
  cmp     edx, eax
  jl      another_control
  jmp     continue_while
another_control:
  cmp     [edi].PointerToRawData, 0
  je      return_value
  sub     edx, [edi].VirtualAddress
  add     edx, [edi].PointerToRawData
return_value:
  pop     ebx
  pop     ecx
  ret
  
continue_while:
  dec     ecx
  add     edi, sizeof IMAGE_SECTION_HEADER
  jmp     while_sections
  
exit_while:
  mov     edx, 0
  pop     ebx
  pop     ecx
  ret
  
RVAToOffset    endp
; -----------------------------------------------------;
;


end    start
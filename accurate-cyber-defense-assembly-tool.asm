; Accuratecyberdefense.asm - x86-64 Assembly Cybersecurity Tool
; Integrates with C functions for network monitoring and threat detection

section .data
    ; Menu strings
    menu_header      db "Accurate Cyber Defense -Advanced Threat Detection Tool", 0xA, 0
    menu_prompt      db "> ", 0
    menu_help        db "Available commands:", 0xA
                     db "help           - Show this help", 0xA
                     db "ping <ip>      - Ping an IP address", 0xA
                     db "tracert <ip>   - Trace route to IP", 0xA
                     db "start <ip>     - Start monitoring IP for threats", 0xA
                     db "stop           - Stop monitoring", 0xA
                     db "view           - View detected threats", 0xA
                     db "status         - Show monitoring status", 0xA
                     db "clear          - Clear screen", 0xA
                     db "exit           - Exit program", 0xA, 0
    
    ; Status messages
    status_monitoring db "Monitoring active for IP: ", 0
    status_inactive    db "Monitoring inactive", 0xA, 0
    status_stopped     db "Monitoring stopped", 0xA, 0
    status_started     db "Started monitoring IP: ", 0
    status_cleared     db "Screen cleared", 0xA, 0
    
    ; Error messages
    error_invalid_cmd db "Error: Invalid command", 0xA, 0
    error_ip_missing  db "Error: IP address required", 0xA, 0
    error_no_monitor  db "Error: No active monitoring", 0xA, 0
    
    ; Threat detection messages
    threat_detected   db "THREAT DETECTED: ", 0
    threat_portscan   db "Port scanning activity", 0xA, 0
    threat_dos        db "DoS attack detected", 0xA, 0
    threat_ddos       db "DDoS attack detected", 0xA, 0
    threat_udpflood   db "UDP flood detected", 0xA, 0
    threat_httpflood  db "HTTP flood detected", 0xA, 0
    threat_httpsflood db "HTTPS flood detected", 0xA, 0
    
    ; Other strings
    newline          db 0xA, 0
    clear_screen     db 0x1B, "[H", 0x1B, "[2J", 0  ; ANSI escape codes for clear screen
    
    ; Variables
    current_ip      db 16 dup(0)  ; Store current monitored IP
    is_monitoring   db 0          ; Monitoring flag (0 = false, 1 = true)

section .bss
    input_buffer    resb 256      ; Buffer for user input
    command         resb 32       ; Extracted command
    argument        resb 32       ; Extracted argument

section .text
    global _start
    extern printf, fgets, stdin, strcmp, strtok, inet_addr, exit
    extern start_monitoring, stop_monitoring, check_threats, ping_ip, trace_route

_start:
    ; Display header
    mov rdi, menu_header
    call printf
    
main_loop:
    ; Display prompt
    mov rdi, menu_prompt
    call printf
    
    ; Get user input
    mov rdi, input_buffer
    mov rsi, 256
    mov rdx, [stdin]
    call fgets
    
    ; Parse command
    call parse_input
    
    ; Process command
    call execute_command
    
    ; Loop until exit
    jmp main_loop

; Parse user input into command and argument
parse_input:
    push rbp
    mov rbp, rsp
    
    ; First token (command)
    mov rdi, input_buffer
    mov rsi, newline
    call strtok
    
    test rax, rax
    jz .parse_done
    
    mov rdi, command
    mov rsi, rax
    call strcpy
    
    ; Second token (argument)
    mov rdi, 0
    mov rsi, newline
    call strtok
    
    test rax, rax
    jz .parse_done
    
    mov rdi, argument
    mov rsi, rax
    call strcpy
    
.parse_done:
    pop rbp
    ret

; Execute the parsed command
execute_command:
    push rbp
    mov rbp, rsp
    
    ; Check for 'help' command
    mov rdi, command
    mov rsi, help_cmd
    call strcmp
    test eax, eax
    jz .do_help
    
    ; Check for 'ping' command
    mov rdi, command
    mov rsi, ping_cmd
    call strcmp
    test eax, eax
    jz .do_ping
    
    ; Check for 'tracert' command
    mov rdi, command
    mov rsi, tracert_cmd
    call strcmp
    test eax, eax
    jz .do_tracert
    
    ; Check for 'start' command
    mov rdi, command
    mov rsi, start_cmd
    call strcmp
    test eax, eax
    jz .do_start
    
    ; Check for 'stop' command
    mov rdi, command
    mov rsi, stop_cmd
    call strcmp
    test eax, eax
    jz .do_stop
    
    ; Check for 'view' command
    mov rdi, command
    mov rsi, view_cmd
    call strcmp
    test eax, eax
    jz .do_view
    
    ; Check for 'status' command
    mov rdi, command
    mov rsi, status_cmd
    call strcmp
    test eax, eax
    jz .do_status
    
    ; Check for 'clear' command
    mov rdi, command
    mov rsi, clear_cmd
    call strcmp
    test eax, eax
    jz .do_clear
    
    ; Check for 'exit' command
    mov rdi, command
    mov rsi, exit_cmd
    call strcmp
    test eax, eax
    jz .do_exit
    
    ; Invalid command
    mov rdi, error_invalid_cmd
    call printf
    jmp .done
    
.do_help:
    mov rdi, menu_help
    call printf
    jmp .done
    
.do_ping:
    ; Check if IP provided
    cmp byte [argument], 0
    je .missing_ip
    
    ; Call C ping function
    mov rdi, argument
    call ping_ip
    jmp .done
    
.do_tracert:
    ; Check if IP provided
    cmp byte [argument], 0
    je .missing_ip
    
    ; Call C trace route function
    mov rdi, argument
    call trace_route
    jmp .done
    
.do_start:
    ; Check if IP provided
    cmp byte [argument], 0
    je .missing_ip
    
    ; Validate IP format
    mov rdi, argument
    call inet_addr
    cmp eax, -1
    je .invalid_ip
    
    ; Store IP and start monitoring
    mov rdi, current_ip
    mov rsi, argument
    call strcpy
    
    mov byte [is_monitoring], 1
    
    ; Call C start monitoring function
    mov rdi, argument
    call start_monitoring
    
    ; Show status
    mov rdi, status_started
    call printf
    mov rdi, current_ip
    call printf
    mov rdi, newline
    call printf
    jmp .done
    
.do_stop:
    ; Check if monitoring is active
    cmp byte [is_monitoring], 0
    je .not_monitoring
    
    ; Call C stop monitoring function
    call stop_monitoring
    
    mov byte [is_monitoring], 0
    mov rdi, status_stopped
    call printf
    jmp .done
    
.do_view:
    ; Check if monitoring is active
    cmp byte [is_monitoring], 0
    je .not_monitoring
    
    ; Call C check threats function
    call check_threats
    jmp .done
    
.do_status:
    cmp byte [is_monitoring], 0
    je .status_inactive
    
    ; Show active monitoring status
    mov rdi, status_monitoring
    call printf
    mov rdi, current_ip
    call printf
    mov rdi, newline
    call printf
    jmp .done
    
.status_inactive:
    mov rdi, status_inactive
    call printf
    jmp .done
    
.do_clear:
    mov rdi, clear_screen
    call printf
    jmp .done
    
.do_exit:
    ; Stop monitoring if active
    cmp byte [is_monitoring], 1
    jne .exit_now
    
    call stop_monitoring
    
.exit_now:
    mov rdi, 0
    call exit
    
.missing_ip:
    mov rdi, error_ip_missing
    call printf
    jmp .done
    
.invalid_ip:
    mov rdi, error_ip_missing
    call printf
    jmp .done
    
.not_monitoring:
    mov rdi, error_no_monitor
    call printf
    
.done:
    pop rbp
    ret

; Custom strcpy implementation
strcpy:
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    
.loop:
    lodsb
    stosb
    test al, al
    jnz .loop
    
    pop rdi
    pop rsi
    pop rbp
    ret

; Command strings
help_cmd    db "help", 0
ping_cmd    db "ping", 0
tracert_cmd db "tracert", 0
start_cmd   db "start", 0
stop_cmd    db "stop", 0
view_cmd    db "view", 0
status_cmd  db "status", 0
clear_cmd   db "clear", 0
exit_cmd    db "exit", 0
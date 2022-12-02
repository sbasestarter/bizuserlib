# bizuserlib

```stack 
call user-manager.register_begin, return register_user_pass[event], bizID
    call user-pass.register_begin, return register_phone[event] - add callback user-pass.register_end
        call phone.register_begin, return ok - add callback phone.register_end
            call phone.post_code
            call phone.check_code, return ok
        call phone.register_check, return ok, set register_phone[event] and verify_phone[event] completed
    call user-pass.register_check, return ok, set register_user-pass[event] and verify_user-pass[event] completed
call user-manager.register_check, return register_google2fa[event] - add callback google2fa.register_end
    call google2fa.register_begin, [need verify_phone[event], checked it completed] return ok
    call google2fa.register_check, return ok, set register_google2fa[event] and verify_google2fa[event] completed
call user-manager.register_check, return ok
call user-manager.register_end
    call user-pass.register_end
    call hone.register_end
    call google2fa.register_end
    
call user-manager.login_begin, return verify_user_pass[event], bizID
    call user-pass.verify, set verify_user_pass[event] completed
call user-manager.login_check, return verify_phone[event]
    call phone.verify, set verify_phone[event] completed
call user-manager.login_check, return register_google2fa[event]
    call google2fa.register_begin, [need verify_phone[event], checked it completed] return ok
    call google2fa.register_check, return ok, set register_google2fa[event] and verify_google2fa[event] completed
call user-manager.login_end, return ok and token
```

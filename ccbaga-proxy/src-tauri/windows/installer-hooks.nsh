; [INPUT]: Tauri NSIS 的当前用户安装目录和固定 CCBaga-Proxy-B 名称空间。
; [OUTPUT]: B 独立启动项及卸载时的本应用注册项清理。
; [POS]: 安装器窄钩子；不执行 SSH，不删除资料，不改其他浏览器关联。
; [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
!macro NSIS_HOOK_POSTINSTALL
  CreateShortCut "$SMPROGRAMS\CCBaga-Proxy-B.lnk" "$INSTDIR\requirement-french.exe" "--browser" "$INSTDIR\browser-runtime\icons\browser.ico" 0
!macroend
!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$SMPROGRAMS\CCBaga-Proxy-B.lnk"
  DeleteRegKey HKCU "Software\Clients\StartMenuInternet\CCBaga-Proxy-B"
  DeleteRegKey HKCU "Software\Classes\CCBaga-Proxy-B.URL"
  DeleteRegKey HKCU "Software\Classes\CCBaga-Proxy-B.HTML"
  DeleteRegValue HKCU "Software\RegisteredApplications" "CCBaga-Proxy-B"
!macroend

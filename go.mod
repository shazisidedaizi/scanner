module github.com/shazisidedaizi/scanner

go 1.24

require (
    github.com/cheggaaa/pb/v3 v3.1.5
    golang.org/x/net v0.25.0
    golang.org/x/sys v0.18.0 // 新增：用于 unix 系统调用
    golang.org/x/time v0.14.0 // 新增：用于 rate 限速器
)

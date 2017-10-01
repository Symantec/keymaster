package main

import (
	"bufio"
	"fmt"
	"net/http"

	"github.com/Symantec/Dominator/lib/html"
)

type adminDashboardType struct {
	htmlWriter html.HtmlWriter
}

func newAdminDashboard(htmlWriter html.HtmlWriter) *adminDashboardType {
	return &adminDashboardType{
		htmlWriter: htmlWriter,
	}
}

func (dashboard *adminDashboardType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	writer := bufio.NewWriter(w)
	defer writer.Flush()
	fmt.Fprintln(writer, "<title>keymaster status page</title>")
	fmt.Fprintln(writer, "<body>")
	fmt.Fprintln(writer, "<center>")
	fmt.Fprintln(writer, "<h1>keymaster status page</h1>")
	fmt.Fprintln(writer, "</center>")
	html.WriteHeaderWithRequest(writer, req)
	fmt.Fprintln(writer, "<h3>")
	dashboard.htmlWriter.WriteHtml(writer)
	fmt.Fprintln(writer, "</h3>")
	fmt.Fprintln(writer, "<hr>")
	html.WriteFooter(writer)
	fmt.Fprintln(writer, "</body>")
}

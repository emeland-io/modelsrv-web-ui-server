package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
	"go.emeland.io/modelsrv-web-ui-server/internal/proxy"
)

var _ = Describe("SingleHostReverseProxy identity headers", func() {
	const auditorGroup = "audit-group"

	var (
		backend       *httptest.Server
		target        *url.URL
		rp            *httputil.ReverseProxy
		gotSubject    string
		gotGroups     string
		gotAuditor    string
		clientReq     *http.Request
		enrichedReq   *http.Request
		proxyResponse *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		gotSubject = ""
		gotGroups = ""
		gotAuditor = ""

		backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSubject = r.Header.Get(proxy.HeaderAuthSubject)
			gotGroups = r.Header.Get(proxy.HeaderAuthGroups)
			gotAuditor = r.Header.Get(proxy.HeaderAuthAuditor)
			w.WriteHeader(http.StatusOK)
		}))

		var err error
		target, err = url.Parse(backend.URL)
		Expect(err).NotTo(HaveOccurred())

		rp = proxy.NewSingleHostReverseProxy(target, auditorGroup)
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}

		clientReq = httptest.NewRequest(http.MethodGet, "/api/systems", nil)
		clientReq.Header.Set("Authorization", "Bearer user-1")
		clientReq.Header.Set("X-Groups", "team-a,audit-group")
		clientReq.Header.Set(proxy.HeaderAuthSubject, "spoofed-subject")
		clientReq.Header.Set(proxy.HeaderAuthAuditor, "true")

		auth.StubMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			enrichedReq = r
		})).ServeHTTP(httptest.NewRecorder(), clientReq)

		proxyResponse = httptest.NewRecorder()
		rp.ServeHTTP(proxyResponse, enrichedReq)
	})

	AfterEach(func() {
		backend.Close()
	})

	It("forwards the request successfully", func() {
		Expect(proxyResponse.Code).To(Equal(http.StatusOK))
	})

	It("injects the authenticated subject from context", func() {
		Expect(gotSubject).To(Equal("user-1"))
	})

	It("injects groups from context as a comma-separated header", func() {
		Expect(gotGroups).To(Equal("team-a,audit-group"))
	})

	It("marks auditors when the caller belongs to the configured auditor group", func() {
		Expect(gotAuditor).To(Equal("true"))
	})

	It("strips spoofed X-Auth-* headers from the client", func() {
		Expect(gotSubject).NotTo(Equal("spoofed-subject"))
	})
})

var _ = Describe("SingleHostReverseProxy non-auditor identity headers", func() {
	const auditorGroup = "audit-group"

	var (
		backend       *httptest.Server
		target        *url.URL
		rp            *httputil.ReverseProxy
		gotSubject    string
		gotGroups     string
		gotAuditor    string
		clientReq     *http.Request
		enrichedReq   *http.Request
		proxyResponse *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		gotSubject = ""
		gotGroups = ""
		gotAuditor = ""

		backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSubject = r.Header.Get(proxy.HeaderAuthSubject)
			gotGroups = r.Header.Get(proxy.HeaderAuthGroups)
			gotAuditor = r.Header.Get(proxy.HeaderAuthAuditor)
			w.WriteHeader(http.StatusOK)
		}))

		var err error
		target, err = url.Parse(backend.URL)
		Expect(err).NotTo(HaveOccurred())

		rp = proxy.NewSingleHostReverseProxy(target, auditorGroup)
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}

		clientReq = httptest.NewRequest(http.MethodGet, "/api/systems", nil)
		clientReq.Header.Set("Authorization", "Bearer owner-1")
		clientReq.Header.Set("X-Groups", "team-a")
		clientReq.Header.Set(proxy.HeaderAuthAuditor, "true")
		clientReq.Header.Set(proxy.HeaderAuthGroups, "spoofed-groups")

		auth.StubMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			enrichedReq = r
		})).ServeHTTP(httptest.NewRecorder(), clientReq)

		proxyResponse = httptest.NewRecorder()
		rp.ServeHTTP(proxyResponse, enrichedReq)
	})

	AfterEach(func() {
		backend.Close()
	})

	It("forwards the request successfully", func() {
		Expect(proxyResponse.Code).To(Equal(http.StatusOK))
	})

	It("injects the authenticated subject from context", func() {
		Expect(gotSubject).To(Equal("owner-1"))
	})

	It("injects groups from context", func() {
		Expect(gotGroups).To(Equal("team-a"))
	})

	It("omits X-Auth-Auditor for non-auditors", func() {
		Expect(gotAuditor).To(BeEmpty())
	})

	It("strips spoofed X-Auth-Groups from the client", func() {
		Expect(gotGroups).NotTo(Equal("spoofed-groups"))
	})
})

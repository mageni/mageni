# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114220");
  script_version("2023-12-14T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-12-14 05:05:32 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 15:03:30 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 17:43:00 +0000 (Fri, 08 Apr 2022)");

  script_cve_id("CVE-2022-22965");

  script_name("VMware Spring Framework RCE Vulnerability (Spring4Shell, SpringShell) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22965");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement#suggested-workarounds");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/04/01/spring-framework-rce-mitigation-alternative");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/5grm3b0g6co2rcw3tov34vx8r3ws9x6y");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/k1oknlyc28x25k3tnr9chr8wc37yrxlw");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/4318xzl2f9o8j3x56gx46vlst5myroc0");
  script_xref(name:"URL", value:"https://www.praetorian.com/blog/spring-core-jdk9-rce/");
  script_xref(name:"URL", value:"https://blog.sonatype.com/new-0-day-spring-framework-vulnerability-confirmed");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/");
  script_xref(name:"URL", value:"https://bugalert.org/content/notices/2022-03-30-spring.html");
  script_xref(name:"URL", value:"https://www.intruder.io/blog/spring4shell-cve-2022-22965");
  script_xref(name:"URL", value:"https://twitter.com/RandoriAttack/status/1509298490106593283");
  script_xref(name:"URL", value:"https://github.com/alt3kx/CVE-2022-22965");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to a remote code execution
  (RCE) vulnerability dubbed 'Spring4Shell' or 'SpringShell'.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the received HTTP
  status code.

  Notes:

  - This VT has a low Quality of Detection (QoD) because a check for this flaw in a non-intrusive
  way (means not writing a web shell to the target) can be only done based on a HTTP status code
  received to a specific payload request. This is the least reliable method which could cause false
  positives, thus a lower QoD had to be chosen.

  - Due  to the possible false positives and limited known affected targets this VT needs to be
  enable via 'Enable generic web application scanning' within the VT 'Global variable settings'
  (OID: 1.3.6.1.4.1.25623.1.0.12288).");

  script_tag(name:"insight", value:"A Spring MVC or Spring WebFlux application running on JDK 9+ may
  be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the
  application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot
  executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the
  vulnerability is more general, and there may be other ways to exploit it.");

  script_tag(name:"affected", value:"VMware Spring Framework versions prior to 5.2.20 and 5.3.x
  prior to 5.3.18.

  The following are the requirements for an environment to be affected to this specific
  vulnerability:

  - Running on JDK 9 or higher

  - Apache Tomcat as the Servlet container

  - Packaged as a traditional WAR and deployed in a standalone Tomcat instance. Typical Spring Boot
  deployments using an embedded Servlet container or reactive web server are not impacted.

  - spring-webmvc or spring-webflux dependency

  - an affected version of the Spring Framework");

  script_tag(name:"solution", value:"Update to version 5.2.20, 5.3.18 or later.

  Possible mitigations without doing an update:

  - Upgrading Tomcat (10.0.20, 9.0.62 or 8.5.78 hardened the class loader to provide a mitigation)

  - Downgrading to Java 8

  - Disallowed Fields

  Please see the references for more information on these mitigation possibilities.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  # nb: Might run a good amount of time depending on the found dirs
  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

# nb: We also don't want to run if optimize_test is set to "no"
if( http_is_cgi_scan_disabled() ||
    get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

ownip = this_host();
targetip = get_host_ip();

# nb: No need to run against a GOS / GSM as we know that the system isn't using Spring Cloud
# Function at all and thus waste scanning time on self scans.
if( executed_on_gos() ) {
  if( ownip == targetip || islocalhost() ) {
    exit( 99 ); # EXIT_NOTVULN
  }
}

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/";
  req1 = http_get( port:port, item:url );
  res1 = http_keepalive_send_recv( port:port, data:req1 );
  if( ! res1 || res1 !~ "^HTTP/1\.[01] [0-9]+" || # nb: No "correct" HTTP response
      res1 =~ "^HTTP/1\.[01] 400" )               # nb: False positive check (if the target is directly throwing a 400 status code)
    continue;

  # From https://twitter.com/RandoriAttack/status/1509298490106593283 which mentions that an
  # affected system is throwing a 400 status code on such a request.
  url += "?class.module.classLoader.URLs%5B0%5D=0";
  req2 = http_get( port:port, item:url );
  res2 = http_keepalive_send_recv( port:port, data:req2 );
  if( ! res2 || res2 !~ "^HTTP/1\.[01] [0-9]+" ) # nb: No "correct" HTTP response
    continue;

  if( res2 =~ "^HTTP/1\.[01] 400" ) {

    headers1 = http_extract_headers_from_response( data:res1 );
    headers2 = http_extract_headers_from_response( data:res2 );

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    report  = 'After doing a HTTP request with the following data:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += "a received status code of '400' indicates that the target is affected.";

    # nb: Usually both of these shouldn't be empty but still checking them for consistency reasons.
    if( headers2 )
      report += '\n\nResult (Header):\n\n' + headers2;

    if( headers1 )
      report += '\n\nResult to initial "probing" without a malicious payload (Header):\n\n' + headers1;

    expert_info  = 'Request 1:\n'+ req1 + 'Response 1:\n' + res1;
    expert_info += 'Request 2:\n'+ req2 + 'Response 2:\n' + res2;
    security_message( port:port, data:report, expert_info:expert_info );
    exit( 0 );
  }
}

exit( 0 ); # Unclear reliability so no exit(99); here...

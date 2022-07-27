###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bugtrackernet_mult_vuln.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# BugTracker.NET Multiple Security Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ifdefined:bugtracker.net";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901303");
  script_version("$Revision: 11855 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-29 15:57:44 +0530 (Thu, 29 Nov 2012)");
  script_name("BugTracker.NET Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51292/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/117");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118152/bugtracker-sqldisclose.tgz");
  script_xref(name:"URL", value:"http://www.defensecode.com/public/BugTrackerNet_Security_Audit_Final_Report.pdf");
  script_xref(name:"URL", value:"http://www.defensecode.com/article/bugtracker.net_multiple_security_vulnerabilities-31");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_bugtracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BugTrackerNET/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain sensitive information
  by performing SQL injection, XSS, file disclosure and HTTP response
  splitting attacks on the affected application and execute arbitrary script
  code.");
  script_tag(name:"affected", value:"BugTracker.NET version 3.5.8 and prior");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied input.
  SQL injection:

  - 'row_id.Value', 'sql' parameter in dbutil.cs
  File Disclosure:

  - 'path' parameters in view_web_config.aspx

  - 'which_file', 'file_name', 'path' parameters in edit_custom_html.aspx

  - 'filename', 'path' parameters in download_file.aspx
  Cross Site Scripting:

  - 'tags' parameter in bug_list.cs

  - 'path', 'blame_text' parameter in svn_blame.aspx

  - 'commit1', 'unified_diff_text', 'error' parameters in git_diff.aspx

  - 'Request', 'path' parameters in view_web_config.aspx

  - 'filename', 'path' parameters in download_file.aspx

  - 'path', 'raw_text' parameters in svn_blame.aspx

  - 'msg' parameter in default.aspx

  - 'revision', 'rev' parameters in hg_blame.asp

  - 'qs', 'url' parameters in util.cs
  HTTP Response Splitting:

  - 'url' parameter in util.cs

  - 'bg_id' parameter in delete_subscriber.aspx");
  script_tag(name:"solution", value:"Upgrade to BugTracker.NET 3.8.9");
  script_tag(name:"summary", value:"This host is installed with BugTracker.NET and is prone to SQL injection or
  XSS or file disclosure or HTTP response splitting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://ifdefined.com/bugtrackernet.html");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

xss = "<script>alert%28'document.cookie'%29</script>";
url = dir + "/default.aspx?msg=" + xss;

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"<script>alert\('document.cookie'\)</script>" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
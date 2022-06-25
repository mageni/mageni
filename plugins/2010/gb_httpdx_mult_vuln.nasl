###############################################################################
# OpenVAS Vulnerability Test
#
# httpdx Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801236");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2009-4769", "CVE-2009-4770");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("httpdx Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3312");
  script_xref(name:"URL", value:"http://www.metasploit.com/redmine/projects/framework/repository/revisions/7569/entry/modules/exploits/windows/http/httpdx_tolog_format.rb");
  script_xref(name:"URL", value:"http://www.metasploit.com/redmine/projects/framework/repository/revisions/7569/entry/modules/exploits/windows/ftp/httpdx_tolog_format.rb");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_httpdx_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("httpdx/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash an affected server or
  execute arbitrary code by sending a malicious command to a vulnerable server.");

  script_tag(name:"affected", value:"httpdx version 1.5 and prior.");

  script_tag(name:"insight", value:"The multiple flaws are,

  - default password of pass123 for the moderator account, which makes it
  easier for remote attackers to obtain privileged access.

  - format string error in tolog function in the FTP server and HTTP server
  when processing user-supplied commands.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to httpdx Server version 1.5.4 or later.");

  script_tag(name:"summary", value:"This host is installed with httpdx and is prone to multiple
  vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

httpdxPort = get_http_port(default:80);

httpdxVer = get_kb_item("httpdx/" + httpdxPort + "/Ver");
if(!isnull(httpdxVer))
{
  if(version_in_range(version:httpdxVer, test_version:"1.4", test_version2:"1.5")){
    security_message(httpdxPort);
  }
}


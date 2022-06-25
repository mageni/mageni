###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_diagnostics_server_magentservice_bof_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# HP Diagnostics Server 'magentservice.exe' Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802386");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2011-4789");
  script_bugtraq_id(51398);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-01 14:14:14 +0530 (Wed, 01 Feb 2012)");
  script_name("HP Diagnostics Server 'magentservice.exe' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47574/");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jan/88");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-016/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_hp_diagnostics_server_detect.nasl");
  script_require_ports("Services/www", 2006);
  script_mandatory_keys("hpdiagnosticsserver/installed");
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code within the context of the application or cause a denial of service
condition.");
  script_tag(name:"affected", value:"HP Diagnostics Server 9.00");
  script_tag(name:"insight", value:"The flaw is due to an error within the magentservice.exe process
when processing a specially crafted request sent to TCP port 23472 and causing
a stack-based buffer overflow.");
  script_tag(name:"summary", value:"This host is running HP Diagnostics Server and is prone to
buffer overflow vulnerability.");
  script_tag(name:"solution", value:"Upgrade to HP LoadRunner 11.0 patch4 or later.");
  script_xref(name:"URL", value:"http://www.hp.com/");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

hpdsPort = get_http_port(default:2006);
hpdsVer = get_kb_item("www/" + hpdsPort+ "/HP/Diagnostics_Server/Ver");
if(hpdsVer)
{
  if(version_is_equal(version:hpdsVer, test_version:"9.00")){
    security_message(port:hpdsPort);
  }
}

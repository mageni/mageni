##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_cmd_exec_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Open Ticket Request System (OTRS) Command Execution Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801766");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-0456");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_name("Open Ticket Request System (OTRS) Command Execution Vulnerability");



  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute an arbitrary OS
command with the privileges of OTRS on the server where it is installed.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to certain unspecified input is not properly sanitised before
being used. This can be exploited to inject and execute shell commands.");
  script_tag(name:"solution", value:"Upgrade to Open Ticket Request System (OTRS) version 2.3.5 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Open Ticket Request System (OTRS) and is prone to command
execution bulnerability.");
  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) version prior to 2.3.5");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38507/");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN73162541/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000019.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  script_xref(name:"URL", value:"http://otrs.org/download/");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:port))
{
  if(version_is_less_equal(version:vers, test_version:"2.3.4"))
  {
    security_message(port:port);
  }
}

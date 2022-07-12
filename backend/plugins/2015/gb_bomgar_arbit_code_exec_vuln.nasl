###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bomgar_arbit_code_exec_vuln.nasl 49579 2015-06-22 17:25:26Z june$
#
# Bomgar Remote Support Arbitrary Code Execution Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:bomgar:remote_support";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805800");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-0935");
  script_bugtraq_id(74460);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-22 17:33:34 +0530 (Mon, 22 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Bomgar Remote Support Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"The host is running Bomgar Remote Support
  and prone to arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws is in the portal application that is
  triggered when deserializing untrusted input using the unserialize() function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to inject PHP objects and execute arbitrary code.");

  script_tag(name:"affected", value:"Bomgar Remote Support version before
  15.1.1");

  script_tag(name:"solution", value:"Update to version 15.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/978652");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bomgar_remote_support_detect.nasl");
  script_mandatory_keys("Bomgar/installed");
  script_xref(name:"URL", value:"http://www.bomgar.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!bomgarPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!bomgarVer = get_app_version(cpe:CPE, port:bomgarPort)){
  exit(0);
}

if(version_is_less(version:bomgarVer, test_version:"15.1.1"))
{
  report = 'Installed version: ' + bomgarVer + '\n' +
           'Fixed version:     15.1.1'  + '\n';
  security_message(data:report, port:bomgarPort);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moziloCMS_mult_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# moziloCMS Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilo:mozilocms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801076");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-09 07:52:52 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4209");
  script_bugtraq_id(35212);
  script_name("moziloCMS Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mozilloCMS_detect.nasl");
  script_mandatory_keys("mozillocms/detected");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/388498.php");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/35212.txt");
  script_xref(name:"URL", value:"http://cms.mozilo.de/index.php?cat=10_moziloCMS&page=50_Download");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"moziloCMS version 1.11.1 and prior on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to an error in 'admin/index.php'. The input
  values are not properly verified before being used via 'cat' and file parameters in an 'editsite' action.");

  script_tag(name:"solution", value:"Upgrade to version 1.12 or later.");

  script_tag(name:"summary", value:"The host is running moziloCMS and is prone to multiple Cross Site
  Scripting Vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if (vers && version_is_less_equal(version: vers, test_version: "1.11.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.12", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mul_full_path_info_disc_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Joomla! CVE-2017-8057 Multiple Full Path Information Disclosure Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107158");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-27 14:05:12 +0200 (Thu, 27 Apr 2017)");
  script_cve_id("CVE-2017-8057");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Joomla! CVE-2017-8057 Multiple Full Path Information Disclosure Vulnerabilities");
  script_tag(name:"summary", value:"Joomla is vulnerable to multiple full path information
  disclosure vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Remote attackers can exploit these issues to obtain sensitive
  information that may lead to further attacks.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information.");
  script_tag(name:"affected", value:"Joomla! 3.4.0 through 3.6.5 are vulnerable");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor
  advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98028");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port: Port)){
  exit(0);
}

if(version_in_range(version: Ver, test_version:"3.4.0", test_version2: "3.6.5"))
{
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"3.7.0");
  security_message(data:report, port: Port);
  exit(0);
}

exit(99);

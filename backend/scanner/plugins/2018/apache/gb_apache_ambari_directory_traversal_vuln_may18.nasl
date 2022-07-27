###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Ambari Directory Traversal Vulnerability May18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812875");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8003");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-08 12:47:50 +0530 (Tue, 08 May 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Ambari Directory Traversal Vulnerability May18");

  script_tag(name:"summary", value:"This host is running Apache Ambari and is
  prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Apache Ambari unable
  to sanitize against a crafted HTTP request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to craft an HTTP request which provides read-only access to any file on the
  filesystem of the host.");

  script_tag(name:"affected", value:"Apache Ambari versions from 1.4.0 through 2.6.1.");

  script_tag(name:"solution", value:"Upgrade to Apache Ambari version 2.6.2 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-CVE-2018-8003");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Installation+Guide+for+Ambari+2.6.2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_detect.nasl");
  script_mandatory_keys("Apache/Ambari/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!aport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:aport, exit_no_version:TRUE)) exit(0);
aver = infos['version'];
apath = infos['location'];

if(version_in_range( version: aver, test_version: "1.4.0", test_version2: "2.6.1"))
{
  report = report_fixed_ver(installed_version:aver, fixed_version:"2.6.2", install_path:apath);
  security_message(port:aport, data:report);
  exit(0);
}
exit(0);

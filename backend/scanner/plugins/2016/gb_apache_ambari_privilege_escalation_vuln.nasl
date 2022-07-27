###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ambari_privilege_escalation_vuln.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Apache Ambari Privilege Escalation Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809085");
  script_version("$Revision: 12363 $");
  script_cve_id("CVE-2015-3270");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-04 16:26:03 +0530 (Fri, 04 Nov 2016)");
  script_name("Apache Ambari Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Ambari
  and is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an access to the user
  resource endpoint is not protected such that an authenticated user can
  remotely escalate his/her permissions to administrative level.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated users to gain administrative privileges, possibly related to
  changing passwords.");

  script_tag(name:"affected", value:"Apache Ambari versions 1.7.0, 2.0.0, 2.0.1,
  2.1.0");

  script_tag(name:"solution", value:"Upgrade to Apache Ambari version 2.0.2 or
  2.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/10/13/3");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_detect.nasl");
  script_mandatory_keys("Apache/Ambari/Installed");
  script_xref(name:"URL", value:"https://ambari.apache.org/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!amb_Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!amb_Ver = get_app_version(cpe:CPE, port:amb_Port)){
  exit(0);
}

if(version_in_range(version:amb_Ver, test_version:"1.7.0", test_version2:"2.0.1"))
{
  fix = "2.0.2";
  VULN = TRUE;
}
else if(version_is_equal(version:amb_Ver, test_version:"2.1.0"))
{
  fix = "2.1.1";
  VULN = TRUE;
}

if(VULN)
{
  report =  report_fixed_ver(installed_version:amb_Ver, fixed_version:fix);
  security_message(data:report, port:amb_Port);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ge_snmp_web_interface_mult_vuln.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# GE SNMP/Web Interface Multiple Vulnerabilities
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

CPE = "cpe:/a:ge:ups_snmp_web_adapter_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807075");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-0861", "CVE-2016-0862");
  script_bugtraq_id(82407);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:29 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("GE SNMP/Web Interface Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with SNMP/Web Interface
  adapter and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Device does not perform strict input validation.

  - File contains sensitive account information stored in cleartext.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary command on the system and to obtain
  sensitive cleartext account information impacting the confidentiality,
  integrity, and availability of the system.");

  script_tag(name:"affected", value:"General Electric (GE) Industrial Solutions
  UPS SNMP/Web Adapter devices with firmware version before 4.8");

  script_tag(name:"solution", value:"Upgrade to GE SNMP/Web Interface adapter
  version 4.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39408");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-033-02");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ge_snmp_web_interface_adapter_detect.nasl");
  script_mandatory_keys("SNMP/Web/Adapter/Installed");
  script_xref(name:"URL", value:"http://www.geindustrial.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!gePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!geVer = get_app_version(cpe:CPE, port:gePort)){
  exit(0);
}

if(version_is_less(version:geVer, test_version:"4.8"))
{
  report = report_fixed_ver(installed_version:geVer, fixed_version:"4.8");
  security_message(port:gePort, data:report);
  exit(0);
}

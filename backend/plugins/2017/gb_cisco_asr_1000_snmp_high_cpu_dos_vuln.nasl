###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asr_1000_snmp_high_cpu_dos_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Cisco ASR 1000 Series Aggregation Services Routers SNMP High CPU DoS Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/h:cisco:asr_1000";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809795");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2017-3820");
  script_bugtraq_id(95934);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-02-06 17:06:10 +0530 (Mon, 06 Feb 2017)");
  script_name("Cisco ASR 1000 Series Aggregation Services Routers SNMP High CPU DoS Vulnerability");

  script_tag(name:"summary", value:"The host is running Cisco ASR 1000 Series
  Aggregation Services router and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect initialized
  variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to increase CPU usage to 99% on an affected device and cause a DoS
  condition.");

  script_tag(name:"affected", value:"Cisco ASR 1000 Series Aggregation Services Routers with versions 15.5(3)S2.1,
  15.6(1)S1.1, 15.4(3)S6, 15.5(3)S2, 15.6(1)S1.");

  script_tag(name:"solution", value:"Upgrade to latest release of Cisco ASR 1000
  Series Aggregation Services router or Cisco IOS XE Software.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux68796");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170201-asrsnmp");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_dependencies("gb_cisco_asr_1000_detect.nasl");
  script_mandatory_keys("cisco_asr_1000/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ciscoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ciscoVers = get_app_version(cpe:CPE, port:ciscoPort)){
  exit(0);
}

if((ciscoVers == "15.5(3)S2.1")||
   (ciscoVers == "15.6(1)S1.1")||
   (ciscoVers == "15.4(3)S6") ||
   (ciscoVers == "15.5(3)S2") ||
   (ciscoVers == "15.6(1)S1"))
{
  report = report_fixed_ver(  installed_version:ciscoVers, fixed_version: "See vendor advisory" );
  security_message( port:ciscoPort, data:report);
  exit(0);
}

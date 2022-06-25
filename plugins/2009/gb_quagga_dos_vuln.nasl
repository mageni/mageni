###############################################################################
# OpenVAS Vulnerability Test
#
# Quagga Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800710");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(34817);
  script_cve_id("CVE-2009-1572");
  script_name("Quagga Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34999");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/05/01/2");
  script_xref(name:"URL", value:"https://marc.info/?l=quagga-dev&m=123364779626078&w=2");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_quagga_detect.nasl");
  script_mandatory_keys("Quagga/Ver");
  script_tag(name:"affected", value:"Quagga version 0.99.11 and prior.");
  script_tag(name:"insight", value:"This flaw is due to an assertion error in the BGP daemon while handling
  an AS path containing multiple 4 byte AS numbers.");
  script_tag(name:"summary", value:"This host is installed with Quagga for Linux and is prone to
  Denial of Service Vulnerability.");
  script_tag(name:"solution", value:"Apply the patch from the referenced mailinglist posting.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the daemon by advertising
  specially crafted AS paths and cause denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

quaggaVer = get_kb_item("Quagga/Ver");
if(!quaggaVer)
  exit(0);

if(version_is_less_equal(version:quaggaVer, test_version:"0.99.11")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

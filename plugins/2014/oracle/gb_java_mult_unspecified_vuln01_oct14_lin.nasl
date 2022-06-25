###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln01_oct14_lin.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108411");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-6558", "CVE-2014-6531", "CVE-2014-6502", "CVE-2014-6512",
                "CVE-2014-6511", "CVE-2014-6506", "CVE-2014-6457");
  script_bugtraq_id(70544, 70572, 70533, 70567, 70548, 70556, 70538);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-20 12:20:38 +0530 (Mon, 20 Oct 2014)");

  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2014 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE JRE
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An unspecified error in share/classes/javax/crypto/CipherInputStream.java script
    related to streaming of input cipher streams.

  - An error in share/classes/java/util/ResourceBundle.java script related to
    property processing and handling of names.

  - An error in the 'LogRecord::readObject' function in
    classes/java/util/logging/LogRecord.java related to handling of resource bundles.

  - An error related to the wrapping of datagram sockets in the DatagramSocket
    implementation.

  - An error in share/classes/java/util/logging/Logger.java related to missing
    permission checks of logger resources.

  - An error related to handling of server certificate changes during SSL/TLS
    renegotiation.

  - An error within the 2D subcomponent of the client deployment.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions, disclose sensitive information, manipulate
  certain data, conduct IP spoofing attacks or hijack a mutually authenticated
  session.");

  script_tag(name:"affected", value:"Oracle Java SE 5 update 71 and prior,
  6 update 81 and prior, 7 update 67 and prior, and 8 update 20 and prior on
  Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61609/");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version(cpe:CPE))  {
    exit(0);
  }
}

if(jreVer =~ "^(1\.(5|6|7|8))")
{
  if(version_in_range(version:jreVer, test_version:"1.5.0", test_version2:"1.5.0.71")||
     version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.81")||
     version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.67")||
     version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.20"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
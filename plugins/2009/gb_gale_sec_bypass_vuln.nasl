###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gale_sec_bypass_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Gale EVP_VerifyFinal() Security Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800340");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0047");
  script_bugtraq_id(33150);
  script_name("Gale EVP_VerifyFinal() Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499855");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2008-016.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gale_detect.nasl");
  script_mandatory_keys("Gale/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause spoofing attacks via signature checks on DSA
  and ECDSA keys used with SSL/TLS.");
  script_tag(name:"affected", value:"Gale version 0.99 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of return value in
  EVP_VerifyFinal function of openssl.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Gale and is prone to security bypass
  vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

galePort = 11512;
if(!get_udp_port_state(galePort)){
  exit(0);
}

galeVer = get_kb_item("Gale/Linux/Ver");
if(!galeVer){
  exit(0);
}

# version 0.99 and prior
if(version_is_less_equal(version:galeVer, test_version:"0.99")){
  security_message(galePort);
}

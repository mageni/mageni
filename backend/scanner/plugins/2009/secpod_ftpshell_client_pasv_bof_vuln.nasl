###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftpshell_client_pasv_bof_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# FTPShell Client PASV Command Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:ftpshell:ftpshell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900962");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3364");
  script_bugtraq_id(36327);
  script_name("FTPShell Client PASV Command Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36628");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9613");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53126");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ftpshell_client_detect.nasl");
  script_mandatory_keys("FTPShell/Client/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the user execute arbitrary code
  and crash the application to cause denial of service.");

  script_tag(name:"affected", value:"FTPShell Client 4.1 RC2 and prior.");

  script_tag(name:"insight", value:"A buffer overflow error occurs due to improper bounds checking
  when handling overly long PASV messages sent by the server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running FTPShell Client and is prone to Buffer
  Overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!shellVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:shellVer, test_version:"4.1.RC2")){
  report = report_fixed_ver(installed_version:shellVer, fixed_version:"None");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
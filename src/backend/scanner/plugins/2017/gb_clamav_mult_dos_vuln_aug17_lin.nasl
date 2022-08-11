###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_mult_dos_vuln_aug17_lin.nasl 11900 2018-10-15 07:44:31Z mmartin $
#
# ClamAV Multiple Denial of Service Vulnerabilities Aug17 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811576");
  script_version("$Revision: 11900 $");
  script_cve_id("CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420", "CVE-2017-11423");
  script_bugtraq_id(100154);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 09:44:31 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-08 14:13:11 +0530 (Tue, 08 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV Multiple Denial of Service Vulnerabilities Aug17 (Linux)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper calidation for CHM file in 'mspack/lzxd.c' script in
    libmspack 0.5alpha.

  - An improper calidation for CAB file in cabd_read_string function in
    'mspack/cabd.c' script in libmspack 0.5alpha.

  - An improper validation for e-mail message in 'libclamav/message.c'
    script.

  - An improper validation for PE file in wwunpack function in
    'libclamav/wwunpack.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service or possibly have unspecified other
  impact.");

  script_tag(name:"affected", value:"ClamAV version 0.99.2 on Linux");

  script_tag(name:"solution", value:"Update to version 0.99.3-beta1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/vrtadmin/clamav-devel/commit/a83773682e856ad6529ba6db8d1792e6d515d7f1");
  script_xref(name:"URL", value:"https://github.com/vrtadmin/clamav-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/remote/Ver", "Host/runs_unixoide");
  script_require_ports(3310);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!clamPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!clamVer = get_app_version(cpe:CPE, port:clamPort)){
  exit(0);
}

if(clamVer == "0.99.2")
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.99.3-beta1");
  security_message(data:report, port:clamPort);
  exit(0);
}

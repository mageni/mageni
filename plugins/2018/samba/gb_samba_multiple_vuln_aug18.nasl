###############################################################################
# OpenVAS Vulnerability Test
#
# Samba Multiple Vulnerabilities - Aug18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813783");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-10918", "CVE-2018-1139");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-17 13:10:38 +0530 (Fri, 17 Aug 2018)");
  script_name("Samba Multiple Vulnerabilities - Aug18");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - A missing database output checks on the returned directory attributes from
    the LDB database layer.

  - An error which allows authentication using NTLMv1 over an SMB1 transport
    (either directory or via NETLOGON SamLogon calls from a member server),
    even when NTLMv1 is explicitly disabled on the server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct a denial of service attack and authenticate using NTLMv1 over an SMB1
  transport.");

  script_tag(name:"affected", value:"All versions of Samba from 4.7.0 onwards");

  script_tag(name:"solution", value:"Upgrade to Samba 4.8.4 or 4.7.9 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-10918.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-1139.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-4.7.9.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-4.8.4.html");
  script_xref(name:"URL", value:"https://www.samba.org");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
loc = infos['location'];

if(version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.8")){
  fix = "4.7.9";
}

else if(version_in_range(version:vers, test_version:"4.8.0", test_version2:"4.8.3")){
  fix = "4.8.4";
}

if(fix){
  report = report_fixed_ver( installed_version:vers, fixed_version: fix + " or apply patch", install_path:loc);
  security_message( data:report, port:port);
  exit(0);
}
exit(99);

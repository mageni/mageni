###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k7_total_security_privilege_escalation_vuln_feb15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# K7 Total Security Privilege Escalation Vulnerability Feb15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:k7computing:total_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805454");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9643");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("K7 Total Security Privilege Escalation Vulnerability Feb15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with K7 Total
  Security and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a write-what-where flaw
  in K7Sentry.sys in K7 Computing products that is triggered when handling
  certain IOCTL calls.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to write controlled data to any memory location and execute code with
  kernel-level privileges.");

  script_tag(name:"affected", value:"K7 Total Security before 14.2.0.253
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to K7 Total Security version
  14.2.0.253 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35992/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130246/");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_k7_total_security_detect_win.nasl");
  script_mandatory_keys("K7/TotalSecurity6432/Win/Installed");
  script_xref(name:"URL", value:"http://www.k7computing.co.uk/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!k7usecVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:k7usecVer, test_version:"14.2.0.253"))
{
  report = 'Installed version: ' + k7usecVer + '\n' +
             'Fixed version:     ' + "14.2.0.253" + '\n';
  security_message(data:report );
  exit(0);
}

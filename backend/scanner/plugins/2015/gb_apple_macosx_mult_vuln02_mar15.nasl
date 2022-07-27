###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_mar15.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities -02 Mar15
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805484");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2014-8839", "CVE-2014-8836");
  script_bugtraq_id(72328);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-05 17:54:00 +0530 (Thu, 05 Mar 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities -02 Mar15");
  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The flaw in Spotlight that is triggered as the status of Mails
    'load remote content in messages' setting is not properly checked

  - The flaw in the Bluetooth driver that is triggered can allow a specially
    crafted application to control the size of a write to kernel memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to determine the IP address of the recipient of an email, a local
  attacker to gain elevated privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.10.x through
  10.10.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.10.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT204244");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.10\.");
  script_xref(name:"URL", value:"https://www.apple.com/");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.1"))
  {
    fix = "10.10.2";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version:     ' + fix + '\n';
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
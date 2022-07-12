###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_safari_4_0_5.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Safari 4.0.5 Update
#
# LSS-NVT-2010-010
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102022");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)");
  script_name("Safari 4.0.5 Update");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_cve_id("CVE-2010-0044", "CVE-2010-0046", "CVE-2010-0047", "CVE-2010-0048", "CVE-2010-0049",
               "CVE-2010-0050", "CVE-2010-0051", "CVE-2010-0052", "CVE-2010-0053", "CVE-2010-0054");
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_require_ports("Services/ssh", 22);
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4070");

  script_tag(name:"summary", value:"Installed version of Safari on remote host is older than 4.0.5 and
 contains security vulnerabilities.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  PubSub, WebKit");

  script_tag(name:"solution", value:"Update Safari to newest version. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("AppleSafari/MacOSX/Version");
if (!ver) exit(0);

if (version_is_less(version:ver, test_version:"4.0.5")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
}

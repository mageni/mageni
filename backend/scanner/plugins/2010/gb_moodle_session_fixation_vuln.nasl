###############################################################################
# OpenVAS Vulnerability Test
#
# Moodle Session Fixation Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800767");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1613", "CVE-2010-1616");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Moodle Session Fixation Vulnerability");
  script_xref(name:"URL", value:"http://download.moodle.org");
  script_xref(name:"URL", value:"http://moodle.org/security/");
  script_xref(name:"URL", value:"http://tracker.moodle.org/browse/MDL-17207");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Moodle/Version");

  script_tag(name:"affected", value:"Moodle version 1.8.12 and prior

  Moodle version 1.9.x prior to 1.9.8");

  script_tag(name:"insight", value:"The flaws are exists due to:

  - failure to enable 'Regenerate session id during login', which can be
  exploited to conduct session fixation attacks.

  - creating new roles when restoring a course, which allows teachers to create
  new accounts if they do not have the 'moodle/user:create' capability.");

  script_tag(name:"solution", value:"Upgrade to latest version 1.9.8");

  script_tag(name:"summary", value:"This host is running Moodle and is prone to session fixation vulnerability");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct session
  fixation attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

moodlePort = get_http_port(default:80);

moodleVer = get_kb_item("Moodle/Version");
if(!moodleVer)
  exit(0);

if(version_in_range(version:moodleVer, test_version:"1.8",
   test_version2:"1.8.12") ||  version_in_range(version:moodleVer, test_version:"1.9", test_version2:"1.9.7")){
  security_message(moodlePort);
}

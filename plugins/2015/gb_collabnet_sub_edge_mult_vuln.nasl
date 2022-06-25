###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabnet_sub_edge_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# CollabNet Subversion Edge Management Frontend Multiple Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805710");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-02 13:11:22 +0530 (Thu, 02 Jul 2015)");
  script_name("CollabNet Subversion Edge Management Frontend Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with CollabNet
  Subversion Edge Management Frontend and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version and check
  the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper input sanitization by 'listViewItem' parameter in 'index'
    script.

  - The password are stored in unsalted MD5, which can easily cracked by
    attacker.

  - Does not protect against brute forcing accounts.

  - Does not implement a strong password policy.

  - Does not require the old password for changing the password to a new one.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  read arbitrary local files, bypass authentication mechanisms.");

  script_tag(name:"affected", value:"CollabNet Subversion Edge Management Frontend 4.0.11");

  script_tag(name:"solution", value:"Upgrade to 5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jun/102");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132493/csem-xsrf.txt");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132488/csemfront-passwd.txt");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132494/csem-unsaltedhashes.txt");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132492/csem-passwordpolicy.txt");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3343);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"https://www.open.collab.net");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

coll_Port = get_http_port(default:3343);

foreach dir (make_list_unique("/", "/csvn", cgi_dirs(port:coll_Port)))
{

  if( dir == "/" ) dir = "";

  buf = http_get_cache(item:dir + "/login/auth", port:coll_Port);
  if(!buf) continue;

  if(">CollabNet Subversion Edge Login<" >< buf)
  {
    version = eregmatch(string: buf, pattern: ">Release: ([0-9.]+)",icase:TRUE);

    if (!isnull(version[1]) ) {
      vers=chomp(version[1]);
    }

    if(vers)
    {

      if((version_is_equal(version:vers, test_version:"4.0.11")))
      {
        report = 'Installed Version: ' + vers + '\n' +
                 'Fixed Version:     ' + "5.0" + '\n';

        security_message(data:report, port:coll_Port);
        exit(0);
      }
    }
  }
}

exit(99);
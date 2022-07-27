###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_detect_lin.nasl 12706 2018-12-07 14:02:55Z cfischer $
#
# PHP Version Detection (Linux, local)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103592");
  script_version("$Revision: 12706 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 15:02:55 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2012-10-25 10:12:52 +0200 (Thu, 25 Oct 2012)");
  script_name("PHP Version Detection (Linux, local)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed PHP version on Linux
  and saves the version in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

# Quick Fix until find_bin_multi is implemented
paths = make_list();
phpbin = find_bin( prog_name:"php", sock:sock );
phpclibin = find_bin( prog_name:"php-cli", sock:sock );
php5bin = find_bin( prog_name:"php5", sock:sock );
php7bin = find_bin( prog_name:"php7.0", sock:sock );
if( phpbin ) paths = make_list( paths, phpbin );
if( phpclibin ) paths = make_list( paths, phpclibin );
if( php5bin ) paths = make_list( paths, php5bin );
if( php7bin ) paths = make_list( paths, php7bin );

foreach executableFile( paths ) {

  executableFile = chomp( executableFile );

  if( executableFile == "" ) continue;

  php_ver = get_bin_version( full_prog_name:executableFile, sock:sock, version_argv:"-vn", ver_pattern:"PHP ([^ ]+)" );

  if( ! php_ver[1] || "The PHP Group" >< php_ver[0] ) continue;

  set_kb_item( name:"PHP/Ver/lin", value:php_ver[1] );
  set_kb_item( name:"php/installed", value:TRUE );

  cpe = build_cpe( value:php_ver[1], exp:"([0-9.]+)", base:"cpe:/a:php:php:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:php:php';

  register_product( cpe:cpe, location:executableFile, port:0 );

  log_message( data:build_detection_report( app:"PHP",
                                            version:php_ver[1],
                                            install:executableFile,
                                            cpe:cpe,
                                            concluded:php_ver[0] ),
                                            port:0 );
}

exit( 0 );
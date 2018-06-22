#r "C:\Program Files\Debugging Tools for Windows (x64)\ExtCS.Debugger.dll"
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using ExtCS.Debugger;
using System.Linq;




var d = Debugger.Current;
d.Execute(".prefer_dml 0"); //temporarily turning of DML support and will enable at the end.
var sos = new Extension("sos.dll");//this will load the sos.dll from the right runtime version from PATH C:\Program Files\dotnet\shared\Microsoft.NETCore.App
var mex = new Extension("mex");
string[] linefeed = new string[] { "\n", "\r\n", "\r" };
public Dictionary<string, httpRequest> _httpRequestDict = new Dictionary<string, httpRequest>();
public Dictionary<string, string> _dbgThreadtoOSIDThreadDict = new Dictionary<string, string>();


public class httpRequest
{
    public string _executionContext = "--";
    public string _threadID = "--";
    public string _OSthreadID = "--";
    public string _finished = "--";
    public string _pendingAction = "--";
    public string _runningSince = "--";
   
    //https://github.com/aspnet/KestrelHttpServer/blob/dev/src/Microsoft.AspNetCore.Server.Kestrel/Internal/Http/Frame.cs
    //Microsoft.AspNetCore.Server.Kestrel.Internal.Http.Frame<Microsoft.AspNetCore.Hosting.Internal.HostingApplication+Context>
    public string _httpFrameContext= string.Empty;

    public string _requestPath= "--";
    public string _isPendingActionAsyncMethod = "false";
    public string _sessionID = "--";
    public string _sessionContext = "--";
    
}

public class cookieclass
{
    public string _cookieContext = string.Empty;
    public string _cookieValue = string.Empty;

}



getdbgthreadtoOSIDdict();
getHttpAspNetContext();
getMVCActionContext();
getThreaDIDforASPNetContext();
//getAsyncCallback();
displayOutput();

#region Core Functions

//The getdbgthreadtoOSIDdict creates a mapping between windbg thread ID and the OSID and stores as key value pair in _dbgThreadtoOSIDThreadDict

//0:033 > ~
//#  0  Id: b40.be60 Suspend: 0 Teb: 00007ff7`d57ad000 Unfrozen
//   1  Id: b40.b398 Suspend: 0 Teb: 00007ff7`d57ab000 Unfrozen
//   2  Id: b40.b9f8 Suspend: 0 Teb: 00007ff7`d57a9000 Unfrozen
// 0 ===be60
// 1 ==b398
public void getdbgthreadtoOSIDdict()
{
    string threads = d.Execute("~");
    string[] OSID = returnStringarray(threads);
    string tempId = null;
    string tempOSIDId = null;
    string tempstoreID = null;

    foreach (string osid in OSID)
    {

        tempstoreID = osid.TrimStart('.');
        tempId = tempstoreID.Substring(1, tempstoreID.IndexOf("Id") - 1).Trim();
        tempOSIDId = tempstoreID.Substring(tempstoreID.IndexOf(".") + 1).Trim();
        tempOSIDId = tempOSIDId.Substring(0, tempOSIDId.IndexOf(" ")).Trim();
        _dbgThreadtoOSIDThreadDict.Add(tempOSIDId, tempId);

    }



}


//From Each System.Threading.Thread we try to map threadid to aspnet context.
public void getThreaDIDforASPNetContext()
{
       
    string[] context = returnHeapforMethodTable("!name2ee System.Private.CoreLib.ni.dll System.Threading.Thread");
    httpRequest _temphttpRequestObjct = null;
    string tempthreadcontext = string.Empty;
    string entries = null;
    string threadID = null;
    string dbgthreadID = null;
    string executionContext = null;
    string[] temphttpcontexttype = null;

    foreach (string contextvalue in context)
    {
        if (!contextvalue.Contains("Address"))
        {
            if (contextvalue != string.Empty)
            {
                try
                {
                    tempthreadcontext = contextvalue.Substring(0, 16);
                    threadID = mex.Call("dq " + tempthreadcontext + "+30 L1");
                    threadID = threadID.Substring(19);
                    threadID = Regex.Replace(threadID, @"[^0-9a-zA-Z]+", "");

                    if (threadID.Trim() != "0000000000000000")
                    {
                        threadID = mex.Call("dd " + threadID + "+224 L1");
                        threadID = threadID.Substring(19);
                        threadID = threadID.TrimStart('0');

                    }

                    
                    executionContext = string.Empty;

                    executionContext = d.Execute("dq  " + tempthreadcontext + "+8 L1");
                    executionContext = executionContext.Substring(19);
                    executionContext = Regex.Replace(executionContext, @"[^0-9a-zA-Z]+", "");



                    if (executionContext.Trim() != "0000000000000000")

                    {

                        entries = mex.Call("dq poi(" + executionContext + "+8) +10 L1");
                        entries = entries.Substring(19);
                        entries = Regex.Replace(entries, @"[^0-9a-zA-Z]+", "").Trim();

                        if (entries != "0000000000000000")
                        {

                    
                            temphttpcontexttype = returnStringarray(mex.Call("!do2 poi(" + entries + "+18)"));
                            foreach (var aspnetcontext in temphttpcontexttype)
                            {
                                _httpRequestDict.TryGetValue(aspnetcontext.Substring(2, 16).Trim(), out _temphttpRequestObjct);

                                if (_temphttpRequestObjct._finished == "no")
                                {
                                    if (aspnetcontext.Contains("Microsoft.AspNetCore.Http.DefaultHttpContext"))
                                    {
                                      
                                        _dbgThreadtoOSIDThreadDict.TryGetValue(threadID.Trim(), out dbgthreadID);
                                        _temphttpRequestObjct._threadID = dbgthreadID;
                                        _temphttpRequestObjct._OSthreadID = threadID.Trim();


                                    }
                                }

                                break;
                            }

                        }
                    }
                    
                  
                }
                catch (Exception ex)
                {
                    break;
                }
            }
        }
    }

}

//getHttpAspNetContext picks all the Microsoft.AspNetCore.Http.DefaultHttpContext and gets the processing status of that context ,sessionID and the URL path. It adds those into _httpRequestDict object
public void getHttpAspNetContext()
{

    string[] context = returnHeapforMethodTable("!name2ee Microsoft.AspNetCore.Http.dll Microsoft.AspNetCore.Http.DefaultHttpContext");

    String requestProcessingStatus = null;
    string tempcontext = string.Empty;
    string urlscheme = string.Empty;
    string tempFrameContext = string.Empty;


    foreach (string contextvalue in context)
    {
        if (!contextvalue.Contains("Address"))
        {
            if (contextvalue != string.Empty)
            {
                try
                {
                    httpRequest _httpRequest = new httpRequest();


                    tempcontext = contextvalue.Substring(0, 16);
                    tempFrameContext = mex.Call("dq " + tempcontext + "+30 L1");
                    _httpRequest._httpFrameContext = tempFrameContext.Substring(19).Trim();


                    requestProcessingStatus = mex.Call("dd " + _httpRequest._httpFrameContext + "+1fc L1");

                    if (requestProcessingStatus.Substring(19).Trim() == "00000000")
                    {
                        _httpRequest._finished = "yes";
                        
                    }

                    else
                    {
                        _httpRequest._finished = "no";
                        _httpRequest._requestPath = returnHttpURLOfContext(_httpRequest._httpFrameContext);

                        cookieclass objectcookie= getAspNetCoreSession(_httpRequest._httpFrameContext);
                        _httpRequest._sessionID = objectcookie._cookieValue;
                       // _httpRequest._sessionID = @"CfDJ8MT8CvWji%2FtG";
                        _httpRequest._sessionContext = objectcookie._cookieContext;

                      //  _httpRequest._sessionID.

                    }

                    _httpRequestDict.Add(Regex.Replace(tempcontext, @"[^0-9a-zA-Z]+", ""), _httpRequest);

                }
                catch (Exception ex)
                {
                    break;
                }
            }

        }

    }





}


//Assuming it will be mostly MVC app for .net core so getting the MVC context mapped to httpaspnetContext
public void getMVCActionContext()
{

    string[] actioncontext = returnHeapforMethodTable("!name2ee Microsoft.AspNetCore.Mvc.Abstractions.dll Microsoft.AspNetCore.Mvc.ActionContext");
    String httpcontext = null;
    string tempcontext = string.Empty;
    string action = string.Empty;
    httpRequest _temphttpRequestObjct = null;
    string tempfindasyncfromaction = null;
    foreach (string contextvalue in actioncontext)
    {
        if (!contextvalue.Contains("Address"))
        {
            if (contextvalue != string.Empty)
            {
                try
                {
                    tempcontext = contextvalue.Substring(0, 16);
                    httpcontext = mex.Call("dq " + tempcontext + "+10 L1");
                    action = mex.Call("dq " + tempcontext + "+8 L1");
                    httpcontext = Regex.Replace(httpcontext.Substring(19), @"[^0-9a-zA-Z]+", "").Trim();
                    action = action.Substring(19).Trim();
                    _httpRequestDict.TryGetValue(httpcontext, out _temphttpRequestObjct);

                    if (_temphttpRequestObjct._finished == "no")
                    {
                        _temphttpRequestObjct._pendingAction = action;

                        tempfindasyncfromaction = mex.Call("dq " + action + "+60 L1");
                        tempfindasyncfromaction = mex.Call("dq " + tempfindasyncfromaction.Substring(19).Trim() + "+30 L1");
                        tempfindasyncfromaction = mex.Call("dq " + tempfindasyncfromaction.Substring(19).Trim() + "+18 L1");
                        tempfindasyncfromaction = mex.Call("!do2 " + tempfindasyncfromaction.Substring(19).Trim());

                        if (tempfindasyncfromaction.Contains("System.Threading.Tasks.Task"))
                        {
                            _temphttpRequestObjct._isPendingActionAsyncMethod = "true";

                        }
                    }

                }
                catch (Exception ex)
                {
                    break;
                }
            }

        }

    }

}

//pending implementaion
public void getAsyncCallback()
{
    //string[] context = returnHeapforMethodTable("!name2ee System.Private.CoreLib.ni.dll System.Threading.CancellationCallbackInfo");
 

   
    //string executionContext = string.Empty;
    //string tempthreadcontext = string.Empty;
    //string entries = string.Empty;
    //string tempcontext = string.Empty;

    //foreach (string contextvalue in context)
    //{
    //    if (!contextvalue.Contains("Address"))
    //    {
    //        if (contextvalue != string.Empty)
    //        {
    //            try
    //            {
    //                httpRequest _httpRequest = new httpRequest();


    //                executionContext = string.Empty;

    //                executionContext = d.Execute("dq  " + tempthreadcontext + "+18 L1");
    //                executionContext = executionContext.Substring(19);
    //                executionContext = Regex.Replace(executionContext, @"[^0-9a-zA-Z]+", "");

    //                if (executionContext.Trim() != "0000000000000000")

    //                {

    //                    entries = mex.Call("dq poi(" + executionContext + "+8) +10 L1");
    //                    entries = entries.Substring(19);
    //                    entries = Regex.Replace(entries, @"[^0-9a-zA-Z]+", "").Trim();

    //                    if (entries != "0000000000000000")
    //                    {


    //                        tempcontext = contextvalue.Substring(0, 16);
    //                       tempFrameContext = mex.Call("dq " + tempcontext + "+30 L1");
    //                      _httpRequest._httpFrameContext = tempFrameContext.Substring(19).Trim();


    //                requestProcessingStatus = mex.Call("dd " + _httpRequest._httpFrameContext + "+1fc L1");

    //                if (requestProcessingStatus.Substring(19).Trim() == "00000000")
    //                {
    //                    _httpRequest._finished = "yes";

    //                }

    //                else
    //                {
    //                    _httpRequest._finished = "no";
    //                    _httpRequest._requestPath = returnHttpURLOfContext(_httpRequest._httpFrameContext);

    //                    cookieclass objectcookie = getAspNetCoreSession(_httpRequest._httpFrameContext);
    //                    _httpRequest._sessionID = objectcookie._cookieValue;
    //                    // _httpRequest._sessionID = @"CfDJ8MT8CvWji%2FtG";
    //                    _httpRequest._sessionContext = objectcookie._cookieContext;

    //                    //  _httpRequest._sessionID.

    //                }

    //                _httpRequestDict.Add(Regex.Replace(tempcontext, @"[^0-9a-zA-Z]+", ""), _httpRequest);

    //            }
    //            catch (Exception ex)
    //            {
    //                break;
    //            }
    //        }

    //    }

    //}

}


#endregion


#region HelperFunctions


//This function converts the mutliline string to an array splitted by new lines
public string[] returnStringarray(string objectstring)
{

    return (objectstring.Split(linefeed, StringSplitOptions.RemoveEmptyEntries));

}

//The below functions is similar to !dumpheap -mt MethodTable
//we pass the object for which it gets the mt and then passes the result as an string array.
public string[] returnHeapforMethodTable(string command)
{

    string mtTable = mex.Call(command);
    string mt = getMethodTable(returnStringarray(mtTable));
    string[] context = null;
    String requestProcessingStatus = null;
    string tempcontext = string.Empty;
    string urlscheme = string.Empty;
    
    if (mt != string.Empty)
    {
       context = returnStringarray(mex.Call("!dumpheap -mt " + mt.ToString()));

    }

    return context;
}


//returns methodTable for command !name2ee dll FunctionName
public string getMethodTable(string[] methodtable)
{


    var tempStringforMT = from n in methodtable
            where n.Contains("MethodTable")
            select n;

    foreach (var mt in tempStringforMT)
    {
        //d.Output(x);
        //d.Output("\n");
        if (mt.Contains("MethodTable"))
        {
            return (mt.Substring(12).Trim());
            break;
        }
    }

    return null;
}



//returns the Path of requested URL from the Microsoft.AspNetCore.Server.Kestrel.Internal.Http.Frame

//0:033 > !do 0x000000e18a4fa188
// Name:        Microsoft.AspNetCore.Server.Kestrel.Internal.Http.Frame`1[[Microsoft.AspNetCore.Hosting.Internal.HostingApplication + Context, Microsoft.AspNetCore.Hosting]]
//MethodTable: 00007ffd5a48bfe0
//EEClass:     00007ffd5a499c90
//Size:        568(0x238) bytes

// Fields:
//              MT Field   Offset Type VT Attr            Value Name
//00007ffd5a081520  4000015        8...plicationLifetime  0 instance 000000e189ea4aa0<AppLifetime> k__BackingField

//00007ffdb8744908  400012a      110        System.String  0 instance 000000de0a632328<Path> k__BackingField

public string returnHttpURLOfContext(string frameContext)
{
         
    string url = null;
    url = d.Execute("dq " + frameContext + "+110 L1");

    if (Regex.Replace(url, @"[^0-9a-zA-Z]+", "").Substring(19).Trim() != "0000000000000000")
    {
        url = d.Execute("!do2 " + url.Substring(19));
        url = url.Substring(url.IndexOf("\"/"));
    }
    return url.Trim();
}


                        
public cookieclass getAspNetCoreSession(string frameContext)
{
    cookieclass _cookie = new cookieclass();
    string cookie = string.Empty;
    string[] cookieArray = null;
    string[] cookieStringArray = null;
    cookie = mex.Call("dq " + frameContext + "+158 L1");
    cookie= mex.Call("dq " + cookie.Substring(19) + "+20+190 L1");
    string tempCookie = string.Empty;
    if (Regex.Replace(cookie, @"[^0-9a-zA-Z]+", "") != "0000000000000000")
    {
        tempCookie = cookie.Substring(19);
        cookie = mex.Call("!do " + tempCookie);
        cookieArray = returnStringarray(cookie);



        foreach (var cookieobject in cookieArray)
        {
            if (cookieobject.Contains(".AspNetCore.Session"))
            {

                cookieStringArray = cookieobject.Substring(8).Split(';');

                foreach(var objcookie in cookieStringArray)
                {
                   if(objcookie.Contains(".AspNetCore.Session"))
                    {
                        _cookie._cookieContext = tempCookie;
                        _cookie._cookieValue = objcookie.Substring(cookieobject.IndexOf("=") + 1);
                                               
                        break;
                    }
                   

                }

               
                


                break;
            }

        }

    }

    return _cookie;
}
#endregion




public void displayOutputContext()
{
    
    
    string cmd = null;

    d.Output("context           completed    ThreadId   Path                      PendingAction        IsPendingActionAsync");
    d.Output("\n");
    d.Output("================================================================================================================");
    d.Output("\n");    


    foreach (var item in _httpRequestDict)
    {
        cmd = @"<link cmd=" + "\"" + "!do2 " + item.Key.Trim() + "\"" + ">" + item.Key.Trim() + "</link>";
        d.Output(cmd);
       // d.Output("       ");


        d.Output(item.Value._finished.PadLeft(10));
        //  d.Output("                ");


        if (item.Value._threadID.Trim() != "--")
        {
            cmd = @"<link cmd=" + "\"" + "~~[" + item.Value._OSthreadID + "]s" + ";!t " + item.Value._threadID + "\"" + ">" + item.Value._threadID + "</link>";
            d.Output("        "+cmd);

        }
        else d.Output(item.Value._threadID.PadLeft(10));
        //d.Output("       ");

        if (item.Value._requestPath.Trim() != "--")
        {
            d.Output("    "+item.Value._requestPath.Replace("\"", "").PadLeft(10));
        }
        else
            d.Output(item.Value._requestPath.PadLeft(10));
        //    d.Output("      ");


        if (item.Value._pendingAction.Trim() != "--")
        {
            cmd = @"<link cmd=" + "\"" + "!do2 " + item.Value._pendingAction.Trim() + "\"" + ">" + item.Value._pendingAction.Trim() + "</link>";
            d.Output("                    "+cmd);
           // d.Output("       ");
        }
        else
        {
            d.Output(item.Value._pendingAction.PadLeft(28));
          // d.Output("         ");
        }

        //d.Output("       ");


        d.Output(item.Value._isPendingActionAsyncMethod.PadLeft(30));

        d.Output("\n");
    }


    d.Execute(".prefer_dml 1");

}


public void displayOutput()
{


    string cmd = null;
    d.Output("\n");   
    d.Output("context           completed    ThreadId              Path   PendingMVCAction   PendingActionAsync   SessionID");
    d.Output("\n");
    d.Output("==========================================================================================================================");
    d.Output("\n");


    foreach (var item in _httpRequestDict)
    {
        cmd = @"<link cmd=" + "\"" + "!do2 " + item.Key.Trim() + "\"" + ">" + item.Key.Trim() + "</link>";      
        d.Output(cmd);
       


        d.Output(item.Value._finished.PadLeft(10));
        

        if (item.Value._threadID.Trim() != "--")
        {
            cmd = @"<link cmd=" + "\"" + "~~[" + item.Value._OSthreadID + "]s" + ";!t " + item.Value._threadID + "\"" + ">" + item.Value._threadID + "</link>";

            d.Output("        " + cmd);

        }
        else d.Output(item.Value._threadID.PadLeft(10));
       
        if (item.Value._requestPath.Trim() != "--")
        {
            d.Output(item.Value._requestPath.Replace("\"", "").PadLeft(20,' '));
        }
        else
            d.Output(item.Value._requestPath.PadLeft(20,' '));
     


        if (item.Value._pendingAction.Trim() != "--")
        {
            cmd = @"<link cmd=" + "\"" + "!do2 " + item.Value._pendingAction.Trim() + "\"" + ">" + item.Value._pendingAction.Trim() + "</link>";          
            d.Output("   "+cmd+"   ");
            
        }
        else
        {

            d.Output("   "+item.Value._pendingAction.PadRight(20));
            
        }

      

        if (item.Value._finished == "no")
            d.Output(item.Value._isPendingActionAsyncMethod.PadRight(15));
        else d.Output("--               ");

        if (item.Value._finished == "no")
        {
            if (item.Value._sessionContext != string.Empty)
            {
            
                 cmd = @"<link cmd=" + "\"" + "!do2 " + item.Value._sessionContext.Trim() + "\"" + ">" + item.Value._sessionID.Substring(0,11)+"....." + "</link>";
                 d.Output("   " + cmd + "   ");

             
            }
            else
            d.Output("     --   ");
        }
        else d.Output("   --   ");

        d.Output("\n");
    }


    d.Execute(".prefer_dml 1");
}
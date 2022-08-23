using System;
using RabbitMQ.Client;
using System.Text;
using RabbitMQ.Client.Events;
using System.Threading;
using System.Xml;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Net;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DLMS2AMPQ{

/// <summary>
/// Daemon settings
/// </summary>
[Serializable]
public class DaemonSettings {
    public string HostName = "127.0.0.1";
    public int Port=5672;
    public string VirtualHost="HEX";
    public string UserName="adm";
    public string Password="test";

    public string DebugFile="log.txt";  

    public string InQueue="INDLMS";
    public string OutQueue="OUTDLMS";

    public static DaemonSettings Load(string path){
        try{
                System.IO.StreamReader r = new System.IO.StreamReader(path);
                string s = r.ReadToEnd();
				r.Close();//AB
                return Newtonsoft.Json.JsonConvert.DeserializeObject<DaemonSettings>(s);
        } catch(Exception e){
            return new DaemonSettings(); // empty
        }
    }
    public void Save(string path){
        //                
                System.IO.File.WriteAllText(path,Newtonsoft.Json.JsonConvert.SerializeObject(this,Newtonsoft.Json.Formatting.Indented));
        //
    }
}

/// <summary>
/// Class to pack requests 
/// </summary>
[Serializable]
public class MQTTRequest{
    
    public string MsgID {get;set;}
    public string Cmd {get;set;}

    public string ObisCode {get;set;}

    public string ConnectionString{get;set;}
    public DateTime dtFrom{get;set;}
    public DateTime dtTo{get;set;}
    public MQTTRequest(){
        MsgID="1443";
        Cmd="READ";
        //profiles
        ObisCode="1.0.99.1.0.255";        
        ConnectionString="-S COM4 -c 32 -s 16383 -l 1 -a Low -P 00000000 -t Verbose";
        dtFrom=DateTime.Now.AddDays(-5);
        dtTo=DateTime.Now;
    }
}

/// <summary>
/// Data record
/// </summary>
[Serializable] public class DataRecord{
    public string DateTime {get;set;}
    public string Code {get;set;}
    public string Value {get;set;}
}

/// <summary>
/// Class for packing Reply 
/// </summary>
[Serializable]
public class MQTTReply{
    
    public string InMsgID {get;set;}
    public string MsgID {get;set;}
    public string Status {get;set;}

    public string Error {get;set;}

    public string Reply {get;set;}    
    
    public List<DataRecord>? DataRecords {get;set;}
}



public partial class Programm{
    
    public static bool DispatchMessage(string msg){
try{                  
        MQTTRequest req = Newtonsoft.Json.JsonConvert.DeserializeObject<MQTTRequest>(msg);//System.Text.Json.JsonSerializer.Deserialize<MQTTRequest>(msg);
        string newmessageid=Guid.NewGuid().ToString();        
        string result="";        
        MQTTReply repl= new MQTTReply();
        repl.InMsgID=req.MsgID;
        repl.MsgID=newmessageid;        

        L("Request parse result:"+Object2Json(req));            
        //PROCEED REQUEST

        if(req.Cmd=="READ"){
                var r2=SimpleDLMS.ReadValues(req.ConnectionString,req.ObisCode,req.dtFrom,req.dtTo);
                repl.DataRecords=r2.DataRecords;
                repl.Status=r2.Status;
                repl.Error=r2.Error;
            
        } else {
            repl.Status="notok";
            repl.Error="Unknown command";

        }

        //END PROCEED REQUEST                

        result=Object2Json(repl);
        send2queue(result);

}catch(Exception e){
    L("Dispatching message:"+msg+" got error "+e.Message);
    return false;
}
        return true;
    }
    public static void Receiver(){
        L("Starting consumer");
        var factory = new ConnectionFactory() { HostName = S.HostName, Port=S.Port, VirtualHost=S.VirtualHost, UserName=S.UserName, Password=S.Password };
        factory.AutomaticRecoveryEnabled = true;
        factory.NetworkRecoveryInterval = TimeSpan.FromSeconds(10);
        L("Consumer started, VirtualHost:"+S.VirtualHost+", InQueue:"+S.InQueue+", OutQueue:"+S.OutQueue);

        var connection = factory.CreateConnection();
        var channel = connection.CreateModel();
        
        channel.QueueDeclare(queue: S.InQueue,
                                 durable: true,
                                 exclusive: false,
                                 autoDelete: false,
                                 arguments: null);

        int iLog=0;
        var consumer = new EventingBasicConsumer(channel);
            
        consumer.Received += (model, ea) =>
            {
                var body = ea.Body.ToArray();
                var message = Encoding.UTF8.GetString(body);
                L("Received message: "+message);
                DispatchMessage(message);                
        };
                              
        channel.BasicConsume(queue: S.InQueue,
                                 autoAck: true,
                                 consumer: consumer);
    }


    public static int iLog=1;
    public static object LogLock=new object();
    public static void L(string s){

            lock(LogLock) {
            //TinyLog.LogEntry logEntry= new TinyLog.LogEntry();                        
            string l=iLog+"\t"+DateTime.Now +"\t"+s;
            //logEntry.Message=iLog+"\t"+s;
            //TinyLog.Log.Default.WriteLogEntry(logEntry);
            Console.WriteLine(l+"\r\n");
            try{
            if(S.DebugFile!="")
                System.IO.File.AppendAllText(S.DebugFile,l);

            }catch(Exception e){
                Console.WriteLine("Error with log file "+S.DebugFile+" "+e.Message);

            }

            iLog++;
            }
    }

/// <summary>
/// Send to OUT que
/// </summary>
/// <param name="msg"></param>
    public static void send2queue(string msg){
        L("Sending to "+S.OutQueue+"\t"+msg);

        var factory = new ConnectionFactory() { HostName = S.HostName, Port=S.Port, VirtualHost=S.VirtualHost, UserName=S.UserName, Password=S.Password  };
        using(var connection = factory.CreateConnection())
        using(var channel = connection.CreateModel())
        {
            channel.QueueDeclare(queue: S.OutQueue,
                                 durable: true,
                                 exclusive: false,
                                 autoDelete: false,
                                 arguments: null); 

            channel.BasicPublish(exchange: "",
                                 routingKey: S.OutQueue,
                                 basicProperties: null,
                                 body: Encoding.UTF8.GetBytes(msg));                    
        }
    }


/// <summary>
/// Send to IN queue
/// </summary>
/// <param name="msg"></param>
    public static void send2inqueue(string msg){
        L("Sending to "+S.InQueue+"\t"+msg);

        var factory = new ConnectionFactory() { HostName = S.HostName, Port=S.Port, VirtualHost=S.VirtualHost, UserName=S.UserName, Password=S.Password  };
        using(var connection = factory.CreateConnection())
        using(var channel = connection.CreateModel())
        {
            channel.QueueDeclare(queue: S.InQueue,
                                 durable: true,
                                 exclusive: false,
                                 autoDelete: false,
                                 arguments: null); 

            channel.BasicPublish(exchange: "",
                                 routingKey: S.InQueue,
                                 basicProperties: null,
                                 body: Encoding.UTF8.GetBytes(msg));                    
        }
    }

    
/// <summary>
/// Object to json string
/// </summary>
/// <param name="o"></param>
/// <returns></returns>
public static string Object2Json(object o){
			   
			   JsonSerializerOptions jso = new JsonSerializerOptions();
			   jso.WriteIndented=true;
			   jso.IgnoreNullValues=true;
			   
			return JsonSerializer.Serialize(o, jso);
			/*
			string r="";
			XmlSerializer xsSubmit = new XmlSerializer(typeof(object));
 			using(var sww = new StringWriter())
 			{
     			using(XmlWriter writer = new XmlTextWriter(sww) { Formatting = Formatting.Indented })
     			{
         			xsSubmit.Serialize(writer, o);
         			r = sww.ToString(); // Your XML
     		}
 			}
			return r;
			*/
		}

/// <summary>
/// Settings
/// </summary>    
    public static DaemonSettings S;

/// <summary>
/// Entry point
/// </summary>
/// <param name="args"></param>
    public static int Main(string[] args){

           

            string MyHost=Dns.GetHostName();            
            string ConfigName="config/"+MyHost+".config.json";

            if(!System.IO.Directory.Exists("config")) System.IO.Directory.CreateDirectory("config");
            if(!System.IO.Directory.Exists("logs"))  System.IO.Directory.CreateDirectory("logs");
            S = new DaemonSettings();		              
           
            L("Host:"+MyHost);            
            S=DaemonSettings.Load(ConfigName);            
            S.Save(ConfigName); 

            if(args.Count()>0){                
                if(args[0]=="send" && args.Count()==2){
                    try{
                    // write template
                    if(!File.Exists("example_request.json")){
                        MQTTRequest mr = new MQTTRequest();
                        System.IO.File.WriteAllText("example_request.json",Object2Json(mr));
                    }
                    
                    send2inqueue(System.IO.File.ReadAllText(args[1]));                    

                    }catch(Exception e){
                        Console.WriteLine("Error: "+e.Message);
                        return -1;
                    }
                }

                if(args[0]=="dump"){
                    var factory = new ConnectionFactory() { HostName = S.HostName, Port=S.Port, VirtualHost=S.VirtualHost, UserName=S.UserName, Password=S.Password };
                    factory.AutomaticRecoveryEnabled = true;
                    factory.NetworkRecoveryInterval = TimeSpan.FromSeconds(10);                    
                    var connection = factory.CreateConnection();
                    var channel = connection.CreateModel();        
                    channel.QueueDeclare(queue: S.OutQueue, durable: true, exclusive: false, autoDelete: false, arguments: null);                            
                      
                    for(int i=0;i<50000;i++){
                        var r= channel.BasicGet(queue: S.OutQueue,true);
                        if(r==null)
                            break;
                        var body = r.Body.ToArray();
                        var message = Encoding.UTF8.GetString(body);


                        Console.WriteLine("#"+i+"\n"+message);                                                
                    }
                    
                }
                return 0;
            }
            

            L("Starting receiving thread");
            ThreadStart ts = new ThreadStart(Receiver);
            Thread t = new Thread(ts);
            t.Start();         
            L("Press enter to finish");
            //TODO: convert to daemon
            Console.ReadLine();
            return 0;
    }   
}

/// <summary>
/// Not used
/// </summary>
public class DaemonConfig 
     {
         public string DaemonName { get; set; } 
     }

     public class DaemonService : IHostedService, IDisposable
     {
         private readonly ILogger _logger;
         private readonly IOptions<DaemonConfig> _config;
         public DaemonService(ILogger<DaemonService> logger, IOptions<DaemonConfig> config)
         {
             _logger = logger;
             _config = config;
         }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public Task StartAsync(CancellationToken cancellationToken)
         {

            //Programm.Main2();
            
            return Task.CompletedTask;
         }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }

}
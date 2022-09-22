use packet_sniffer::{list_all_devices, start_capture};

//TODO come mettere in pausa la capture? metto in pausa il thread che la sta eseguendo?
//TODO come riprendere la capture?
//TODO come gestire gli errori ?

fn main() {
    //TODO checking argument -> check error!
    //TODO check if interface has been specified as argument, if not
    //"name": connection status
    list_all_devices();

    //1. TODO insert a network interface connected -> Check error!
    //2. TODO start a capture -> indicate sniffing is ongoing
    start_capture("en3",""); // per adesso solo con ethernet ed eventualmente il TODO filtro
    //3. TODO mettere in pausa una capture
    //4. TODO riprendere una capture
    //5. TODO generare report testuale dopo X secondi in un file passato come argomento

}

use packet_sniffer::{list_all_devices, start_capture, TupleReport};

//come mettere in pausa la capture? metto in pausa il thread che la sta eseguendo?
//come riprendere la capture?
//come considerare una connessione TCP/UDP, basta network/port pairs? Distinguere tra uplink e downlink?
//come calcolare il numero totale di bytes trasmessi (suppongo da calcolare per ogni direzione)?
//come faccio a sapere qual è la prima e l'ultimo pacchetto? uso SYN e FIN?
//come gestire gli errori ?

fn main() {
    //checking argument -> check error!
    //check if interface has been specified as argument, if not
    //"name": connection status
    list_all_devices();

    //1. insert a network interface connected -> Check error!
    //2. start a capture -> indicate sniffing is ongoing
    start_capture("en3"); // per adesso solo con ethernet
    //2b. indicare che lo sniffing process è attivo dopo controlli errori
    //3. mettere in pausa una capture
    //4. riprendere una capture
    //5. generare report testuale dopo X secondi in un file passato come argomento



}
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.text.Collator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;

import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ArffSaver;
import weka.core.converters.ConverterUtils.DataSource;
import weka.filters.unsupervised.attribute.Reorder;

public class ESFSPreBinaryArff {
	boolean zostupne_triedenie = false;
	private class AttribRecord/* implements Comparable<AttribRecord>*/{
		String nazov =  null;
		int index = 0;
		double abs_rozdiel = 0;
		double aktivacii_malware = 0;
		double aktivacii_benign = 0;
		/*@Override
		public int compareTo(ESFSPreBinaryArff.AttribRecord o) {
			if (zostupne_triedenie)
				return Integer.compare(o.aktivacii, aktivacii); // zostupne
			else 
				return Integer.compare(aktivacii, o.aktivacii); // vzostupne
		}*/
		
	};
	
	public ESFSPreBinaryArff(String[] args) {
	//	args = new String[] {
				//"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\s malou upravou\\ember2018-1-5-svec_v2_wv_cls_s42.arff"
				/*
				"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\s malou upravou\\ember2018-1-5-svec_v2_wv_cls_s42_f24.arff",
				"false", // normalize - ignore class distrib.
				"25",
				"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\s malou upravou\\ember2018-1-5-svec_v2_wv_cls_s42_f24-sel.arff",
				*/
				/*
				"d:\\Jan\\habernal - pre Lenku\\fb\\dedup\\pokus moj sort 2cls\\2cls.arff",
				"false",
				"-1",
				"d:\\Jan\\habernal - pre Lenku\\fb\\dedup\\pokus moj sort 2cls\\2cls-sel.arff",
				*/
				
				
//				"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\s malou upravou\\ember2018-1-5-svec_v2_wv_cls_s42.arff",
//				"true",
//				"30",
//				"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\s malou upravou\\ember2018-1-5-svec_v2_wv_cls_s42-sel30N.arff"
				
				/*
				"d:\\Jan\\_DATA\\SME zablokovane komenty\\pokus_BOW 2 nodia_cl_tok_stem\\1k1\\np_bowapi.arff",
				"false",
				"-1",
				"d:\\Jan\\_DATA\\SME zablokovane komenty\\pokus_BOW 2 nodia_cl_tok_stem\\1k1\\np_bowapi-sel-my.arff"
				*/
				//"false"  // absolutny rozdiel true/false
				//ember2018-1-5-svec_v2_wv_cls_s42_f24.arff
		//};
		if (args.length < 4) {System.err.println("error, need 4 args.:\r\n 1. input arff\r\n 2. normalize class distribution [true/false]\r\n 3. resulting attributes count\r\n 4. output arff"); return;}
		
		System.out.println("loading...");
		boolean normalizovat = false;
		if (args[1].equals("true"))
			normalizovat = true;
		boolean absrozdiel = false;
		/*
		if (args[4].equals("true"))
			absrozdiel = true;
			*/
		int max_atributov = -1;		
		max_atributov = Integer.parseInt(args[2]);
		try {
			DataSource vzor = new DataSource(args[0]);
			Instances data;
			data = vzor.getDataSet();
			data.setClass(data.attribute(data.numAttributes()-1));
			Attribute classAttr = data.classAttribute();
			
			HashMap<String,AttribRecord> atributy_vsetky = new HashMap<String,AttribRecord>();
			//HashMap<String,AttribRecord> atributy_benign = new HashMap<String,AttribRecord>();
			//ArrayList<AttribRecord> attr_ = new ArrayList<AttribRecord>(data.numAttributes()); // zostupne zoradene atr., majuce najviac aktivacii (1) pre malware
			//ArrayList<AttribRecord> attr_benign = new ArrayList<AttribRecord>(data.numAttributes()); // zostupne zoradene atr., majuce najviac aktivacii (1) pre benign
			
			// najprv naplnime zoznam malware
			int pocet = 0;
			int pocet_malware = 0;
			int pocet_benign = 0;
			String malw = classAttr.value(0);
			String beni = classAttr.value(1);
			System.out.println("1. class is "+malw);
			System.out.println("2. class is "+beni);
			//System.out.println("computing malware...");
			boolean benigna = false;
			for (int i = 0; i < data.numInstances(); i++) {
				if (pocet == 50000) {
					pocet = 0;
					System.out.println("   "+i);
				}
				Instance inst = data.get(i);
				benigna = false;
				if (inst.stringValue(classAttr).equals(malw)) {   // inst.value(classAttr) - je index nominal hodnoty
					pocet_malware++;
				}else
				if (inst.stringValue(classAttr).equals(beni)) {   // inst.value(classAttr) - je index nominal hodnoty
					pocet_benign++;
					benigna = true;
				} else continue;
				
				pocet++;
				if (benigna)
				for (int a = 0; a < data.numAttributes()-1; a++) {
					Attribute attr = data.attribute(a);
					AttribRecord record = atributy_vsetky.get(attr.name());
					if (record == null) {
						if (inst.value(a) >= 0.5) { // je tu 1
							record = new AttribRecord();
							record.nazov = attr.name();
							record.index = a;							
							record.aktivacii_benign++;
						    atributy_vsetky.put(attr.name(), record);
						}
					}else {
						if (inst.value(a) >= 0.5) // je tu 1
							record.aktivacii_benign++;
					}
				}else
					for (int a = 0; a < data.numAttributes()-1; a++) {
						Attribute attr = data.attribute(a);
						AttribRecord record = atributy_vsetky.get(attr.name());
						if (record == null) {
							if (inst.value(a) >= 0.5) { // je tu 1
								record = new AttribRecord();
								record.nazov = attr.name();
								record.index = a;							
								record.aktivacii_malware++;
							    atributy_vsetky.put(attr.name(), record);
							}
						}else {
							if (inst.value(a) >= 0.5) // je tu 1
								record.aktivacii_malware++;
						}
					}					
			}

			ESFSPreBinaryArff.AttribRecord[] pole = atributy_vsetky.values().toArray(new AttribRecord[0]);
			System.out.println("sorting...");
			// abs rozdiel
			//int max;
			for (AttribRecord rec : pole) {
				//max = Math.max(rec.aktivacii_benign, rec.aktivacii_malware);
				if (normalizovat) {
					rec.aktivacii_benign = rec.aktivacii_benign / pocet_benign;
					rec.aktivacii_malware = rec.aktivacii_malware / pocet_malware;
				}
				//if (absrozdiel)
					rec.abs_rozdiel = Math.abs(rec.aktivacii_benign-rec.aktivacii_malware);
				//else
				//	rec.abs_rozdiel = rec.aktivacii_benign-rec.aktivacii_malware;
			}
			Arrays.sort(pole, new Comparator<ESFSPreBinaryArff.AttribRecord>() {

				@Override
				public int compare(ESFSPreBinaryArff.AttribRecord o1, ESFSPreBinaryArff.AttribRecord o2) {
					return Double.compare(o2.abs_rozdiel, o1.abs_rozdiel); // zhora dole
				}
				
			}.thenComparing(new Comparator<ESFSPreBinaryArff.AttribRecord>() {
/*
				@Override
				public int compare(ESFSPreBinaryArff.AttribRecord o1, ESFSPreBinaryArff.AttribRecord o2) {
					return Double.compare(o1.aktivacii_benign, o2.aktivacii_benign); // zdola hore
				}
			*/	
				@Override
				public int compare(ESFSPreBinaryArff.AttribRecord o1, ESFSPreBinaryArff.AttribRecord o2) {
					return Double.compare(o2.aktivacii_malware, o1.aktivacii_malware); // zdola hore
				}
			}));
			pocet = 0;
			//System.out.println("output 1 malware zostup, benign vzostup...");
			//System.out.println("output 1 max rozdiely vzostup...");
			//System.out.println("pocet malware "+pocet_malware + "  pocet benign "+pocet_benign);
			StringBuilder indexy = new StringBuilder(10000);
			
			//BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\habernal - pre Lenku\\fb\\dedup\\pokus moj sort 2cls\\2cls-stats.csv")));
			//bw.write("attr,cnt1,cnt2,absdiff\r\n");
			//int pc = 1;
			for (AttribRecord rec : pole) {
				//System.out.println((rec.index+1) + " " + rec.nazov + " " + Math.abs(rec.aktivacii_malware-rec.aktivacii_benign));
				indexy.append((rec.index+1)+",");
				pocet++;
				if (max_atributov != -1)
					if (pocet == max_atributov)
						break;
				//bw.write(pc+","+rec.aktivacii_benign + ","+rec.aktivacii_malware+","+rec.abs_rozdiel + "\r\n");
				//pc++;
				//if (pocet > 25) break;
			}
			//bw.close();
			Reorder reord = new Reorder();
			reord.setAttributeIndices(indexy.toString() + "last");
			reord.setInputFormat(data);
			Instances nove = Reorder.useFilter(data, reord);
			//System.out.println(nove.numAttributes());
			
			ArffSaver saver = new ArffSaver();
			saver.setInstances(nove);
			//saver.setDestination(new File(args[3]));
			saver.setFile(new File(args[3]));
			saver.writeBatch();
			
			/*
			ArrayList<AttribRecord> najvacsie_rozdiely = new ArrayList<AttribRecord>(25);			
			System.out.println("output 2 najvacsi rozdiel malw benign...");
			int max_rozdiel = 0;
			int rozdiel;
			HashSet<AttribRecord> maximalne_rozdiely = new HashSet<AttribRecord>();
			AttribRecord maximal = null;
			for (AttribRecord rec : pole) {  // 1. iteracia na najdenie maximalneho rozdielu
				rozdiel = Math.abs(rec.aktivacii_benign-rec.aktivacii_malware);
				if (rozdiel > max_rozdiel) {
					max_rozdiel = rozdiel;
					maximal = rec;
				}
			}
			maximalne_rozdiely.add(maximal);
			// a teraz este 24
			for (AttribRecord rec : pole) {  // 1. iteracia na najdenie maximalneho rozdielu
				rozdiel = Math.abs(rec.aktivacii_benign-rec.aktivacii_malware);
				if (rozdiel > max_rozdiel && !maximalne_rozdiely.contains(rec)) {
					max_rozdiel = rozdiel;
					maximalne_rozdiely.add(rec);
				}
			}*/
			
					
					//.comparing(ESFSPreBinaryArff.AttribRecord::aktivacii_malware).thenComparing(ESFSPreBinaryArff.AttribRecord::aktivacii_benign));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
        new ESFSPreBinaryArff(args);
	}

}
